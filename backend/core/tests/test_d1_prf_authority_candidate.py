"""Candidate-only PostgreSQL tests; no production tables or actual accounts."""
import base64
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import connection, connections, transaction

from core.d1_prf_authority_candidate import (
    TABLE, ProvisionAuthority, Refused, VerifiedContext, canonical, ticket_bytes,
)

pytestmark = pytest.mark.django_db(transaction=True)
ORIGIN = "http://127.0.0.1:8123"
A = VerifiedContext(900001, canonical(["AQIDBA", "BQYHCA", "127.0.0.1", ORIGIN]), 1, 1, "a"*64)
B = replace(A, owner=900002, nonce="b"*64)


@pytest.fixture
def authority():
    assert connection.vendor == "postgresql"
    assert connection.settings_dict["HOST"] == "127.0.0.1"
    assert connection.settings_dict["NAME"] == "test_iamina_phase1_ci"
    connection.ensure_connection()
    assert 160000 <= connection.pg_version < 170000
    with connection.cursor() as cur:
        cur.execute(f"""CREATE TABLE {TABLE} (
            owner bigint PRIMARY KEY CHECK(owner IN (900001, 900002)),
            state text NOT NULL CHECK(state IN ('fresh','legacy','existing','unknown','reserved','redeemed')),
            binding text NOT NULL,
            ticket text, signature bytea,
            CHECK ((state IN ('reserved','redeemed') AND ticket IS NOT NULL AND octet_length(signature)=64 AND signature IS NOT NULL)
                   OR (state NOT IN ('reserved','redeemed') AND ticket IS NULL AND signature IS NULL))
        )""")
    key = ec.generate_private_key(ec.SECP256R1())
    try:
        yield ProvisionAuthority(signing_key=key, origin=ORIGIN), key
    finally:
        with connection.cursor() as cur:
            cur.execute(f"DROP TABLE {TABLE}")


def seed(ctx=A, state="fresh"):
    # Fixture inventory assertion; no runtime method to mark an owner fresh.
    with connection.cursor() as cur:
        cur.execute(f"INSERT INTO {TABLE} (owner,state,binding) VALUES (%s,%s,%s)", [ctx.owner,state,ctx.binding])


def row(ctx=A):
    with connection.cursor() as cur:
        cur.execute(f"SELECT state,ticket,signature FROM {TABLE} WHERE owner=%s", [ctx.owner])
        r = cur.fetchone()
        return (r[0], r[1], bytes(r[2]) if r[2] is not None else None) if r else None


def redeem(service, ctx, envelope):
    return service.redeem(ctx, envelope["ticket"], envelope["signature"])


def test_missing_inventory_refuses(authority):
    service, _ = authority
    with pytest.raises(Refused):
        service.reserve(A)
    assert row() is None


@pytest.mark.parametrize("state", ["legacy", "existing", "unknown"])
def test_nonfresh_inventory_refuses(authority, state):
    service, _ = authority
    seed(state=state)
    with pytest.raises(Refused):
        service.reserve(A)
    assert row() == (state, None, None)


@pytest.mark.parametrize("ctx", [
    replace(A, owner=42), replace(A, epoch=True), replace(A, generation=0),
    replace(A, nonce="x"*64), replace(A, binding=canonical(["AQIDBA=", "BQYHCA", "127.0.0.1", ORIGIN])),
    replace(A, binding=canonical(["AQIDBA", "BQYHCA", "localhost", ORIGIN])),
])
def test_invalid_context_refuses(authority, ctx):
    service, _ = authority
    seed()
    with pytest.raises(Refused):
        service.reserve(ctx)
    assert row() == ("fresh", None, None)


def test_untrusted_mapping_refuses(authority):
    service, _ = authority
    seed()
    with pytest.raises(Refused):
        service.reserve(vars(A))
    assert row() == ("fresh", None, None)


def test_wrong_binding_refuses(authority):
    service, _ = authority
    seed()
    with pytest.raises(Refused):
        service.reserve(replace(A, binding=canonical(["CQoLDA", "BQYHCA", "127.0.0.1", ORIGIN])))
    assert row() == ("fresh", None, None)


def test_signed_roundtrip_and_no_reissue(authority):
    service, _ = authority
    seed()
    envelope = service.reserve(A)
    t = envelope["ticket"]
    assert t["expiresAt"] - t["issuedAt"] == 60000
    assert service.status(A, t["operationId"]) == "reserved"
    with pytest.raises(Refused):
        service.reserve(A)
    # Object key order does not change canonical signed bytes.
    envelope["ticket"] = dict(reversed(list(t.items())))
    assert redeem(service, A, envelope) is True
    assert service.status(A, t["operationId"]) == "redeemed"
    for attempt in (lambda: redeem(service, A, envelope), lambda: service.reserve(A)):
        with pytest.raises(Refused):
            attempt()


@pytest.mark.parametrize("change", ["signature", "nonce", "epoch", "generation", "owner", "operation"])
def test_tampered_redemption_preserves_reservation(authority, change):
    service, _ = authority
    seed()
    e = service.reserve(A)
    original = row()
    t, sig, ctx = dict(e["ticket"]), e["signature"], A
    if change == "signature":
        sig = bytes([sig[0]^1])+sig[1:]
    elif change == "operation":
        t["operationId"] = "c"*64
    elif change == "owner":
        ctx = B
    else:
        ctx = replace(A, **{change: "c"*64 if change == "nonce" else 2})
    with pytest.raises(Refused):
        service.redeem(ctx,t,sig)
    assert row() == original
    assert redeem(service,A,e) is True


def test_expired_reservation_never_reopens(authority):
    service, _ = authority
    seed()
    e = service.reserve(A)
    # Advance only the database comparison via a signed old ticket generated
    # by the fixture signer; no sleep or client clock substitution.
    key = authority[1]
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    t = {**e["ticket"], "issuedAt": e["ticket"]["issuedAt"]-120000,
         "expiresAt": e["ticket"]["expiresAt"]-120000}
    r,s = decode_dss_signature(key.sign(ticket_bytes(t),ec.ECDSA(hashes.SHA256())))
    sig = r.to_bytes(32,"big")+s.to_bytes(32,"big")
    with connection.cursor() as cur:
        cur.execute(f"UPDATE {TABLE} SET ticket=%s,signature=%s WHERE owner=%s", [canonical(t),sig,A.owner])
    with pytest.raises(Refused):
        service.redeem(A,t,sig)
    with pytest.raises(Refused):
        service.reserve(A)
    assert service.status(A,t["operationId"]) == "reserved"


def race(action):
    barrier = Barrier(2)
    def worker():
        try:
            barrier.wait(timeout=5)
            try:
                return action()
            except Refused:
                return False
        finally:
            connections.close_all()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: worker(), range(2)))
    assert sum(x is not False for x in results) == 1
    return next(x for x in results if x is not False)


def test_concurrent_reservation_one_winner(authority):
    service,_ = authority
    seed()
    e = race(lambda: service.reserve(A))
    assert row()[0] == "reserved"
    assert redeem(service,A,e)


def test_concurrent_redemption_one_winner(authority):
    service,_ = authority
    seed()
    e = service.reserve(A)
    assert race(lambda: redeem(service,A,e)) is True
    assert row()[0] == "redeemed"


def test_connection_and_service_recreation_preserve_state(authority):
    service,key = authority
    seed()
    e = service.reserve(A)
    connection.close()
    restarted = ProvisionAuthority(signing_key=key,origin=ORIGIN)
    assert restarted.status(A,e["ticket"]["operationId"]) == "reserved"
    assert redeem(restarted,A,e)
    connection.close()
    restarted = ProvisionAuthority(signing_key=key,origin=ORIGIN)
    assert restarted.status(A,e["ticket"]["operationId"]) == "redeemed"
    with pytest.raises(Refused):
        restarted.reserve(A)


def test_wrong_receipt_and_owner_status_refused(authority):
    service,_ = authority
    seed()
    seed(B)
    e = service.reserve(A)
    with pytest.raises(Refused):
        service.status(A,"c"*64)
    with pytest.raises(Refused):
        service.status(B,e["ticket"]["operationId"])
    assert row(B) == ("fresh",None,None)


def test_atomic_outer_transaction_required(authority):
    service,_ = authority
    seed()
    with transaction.atomic():
        with pytest.raises(Refused):
            service.reserve(A)
    assert row() == ("fresh",None,None)


def test_database_write_failure_rolls_back(authority):
    service,_ = authority
    seed()
    with connection.cursor() as cur:
        cur.execute(f"ALTER TABLE {TABLE} ADD CHECK(state <> 'reserved')")
    with pytest.raises(Refused):
        service.reserve(A)
    assert row() == ("fresh",None,None)


def test_database_missing_table_fails_closed(authority):
    service,_ = authority
    seed()
    with connection.cursor() as cur:
        cur.execute(f"ALTER TABLE {TABLE} RENAME TO {TABLE}_offline")
    try:
        with pytest.raises(Refused):
            service.reserve(A)
    finally:
        with connection.cursor() as cur:
            cur.execute(f"ALTER TABLE {TABLE}_offline RENAME TO {TABLE}")
    assert row() == ("fresh",None,None)


def test_key_mismatch_after_restart_refuses(authority):
    service,_ = authority
    seed()
    e = service.reserve(A)
    foreign = ProvisionAuthority(signing_key=ec.generate_private_key(ec.SECP256R1()),origin=ORIGIN)
    with pytest.raises(Refused):
        redeem(foreign,A,e)
    assert row()[0] == "reserved"
    assert redeem(service,A,e)


def test_python_ticket_verified_by_actual_js(authority):
    service,key = authority
    seed()
    e = service.reserve(A)
    spki = key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    module = Path(__file__).resolve().parents[3]/"frontend/tool/d1_prf_provision_authority_candidate.mjs"
    payload = json.dumps({"ticket":e["ticket"],"signature":list(e["signature"]),
        "spki":base64.b64encode(spki).decode(),"origin":ORIGIN,"module":module.as_uri()})
    script = """
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
const p=JSON.parse(readFileSync(0,'utf8'));
Object.defineProperty(globalThis,'crypto',{value:webcrypto});
Object.defineProperty(globalThis,'CryptoKey',{value:webcrypto.CryptoKey});
Object.defineProperty(globalThis,'location',{value:new URL(p.origin)});
const {createSignedProvisioningAuthority}=await import(p.module);
const key=await crypto.subtle.importKey('spki',Buffer.from(p.spki,'base64'),
  {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
const {owner,binding,epoch,generation,nonce}=p.ticket;
const auth=createSignedProvisioningAuthority({verificationKey:key,redeem:async()=>true});
const grant=await auth.authorize({ticket:p.ticket,signature:new Uint8Array(p.signature)},
  {owner,binding,epoch,generation,nonce},()=>true);
if(auth.consume(grant,owner,binding)?.operationId!==p.ticket.operationId)process.exit(1);
"""
    result = subprocess.run(["node","--input-type=module","-e",script],input=payload,
                            text=True,capture_output=True,timeout=15)
    assert result.returncode == 0, result.stderr
    assert redeem(service,A,e)
