"""Real isolated Django HTTP + Chromium + PostgreSQL candidate tests."""
import base64
import json
import secrets
import threading
import time
import tempfile
from dataclasses import replace
from pathlib import Path
from wsgiref.simple_server import make_server, WSGIRequestHandler

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from django.core.handlers.wsgi import WSGIRequest
from django.db import connections
from django.test import RequestFactory
from playwright.sync_api import sync_playwright

from core.d1_prf_authority_candidate import ProvisionAuthority, canonical
from core.d1_prf_transport_candidate import CandidateTransport, PATH, proof_bytes
from core.tests.test_d1_prf_authority_candidate import authority, A, B, ORIGIN, seed, row

pytestmark = pytest.mark.django_db(transaction=True)


def packet(session, key, action="reserve", payload=None, request_id=None):
    body = json.dumps({"action":action,"requestId":request_id or secrets.token_hex(32),
                       "payload":{} if payload is None else payload},separators=(",",":")).encode()
    r,s = decode_dss_signature(key.sign(proof_bytes(session,body),ec.ECDSA(hashes.SHA256())))
    return body,(r.to_bytes(32,"big")+s.to_bytes(32,"big")).hex()


def send(adapter, session, body, proof, **overrides):
    headers = dict(HTTP_HOST=ORIGIN.split("://")[1], HTTP_ORIGIN=ORIGIN,
                   HTTP_SEC_FETCH_SITE="same-origin", HTTP_X_D1_SESSION=session,
                   HTTP_X_D1_PROOF=proof)
    headers.update(overrides)
    req = RequestFactory().generic("POST",PATH,body,content_type="application/json",**headers)
    res = adapter(req)
    assert res["Cache-Control"] == "no-store"
    assert not res.has_header("Access-Control-Allow-Origin")
    return res.status_code,json.loads(res.content)


@pytest.fixture
def transport(authority):
    service,_ = authority
    seed()
    seed(B)
    key = ec.generate_private_key(ec.SECP256R1())
    adapter = CandidateTransport(service,ORIGIN)
    return adapter,key,adapter.add_verified_fixture(A,key.public_key())


@pytest.mark.parametrize("variant",["missing_proof","wrong_key","wrong_origin","wrong_host","cross_site",
                                  "unknown_session","altered_body","revoked","expired","owner_override"])
def test_refuses_untrusted_http(transport,variant):
    adapter,key,sid = transport
    body,proof = packet(sid,key)
    headers = {}
    if variant == "missing_proof":
        proof = ""
    elif variant == "wrong_key":
        body,proof = packet(sid,ec.generate_private_key(ec.SECP256R1()))
    elif variant == "wrong_origin":
        headers["HTTP_ORIGIN"] = "http://127.0.0.1:9999"
    elif variant == "wrong_host":
        headers["HTTP_HOST"] = "localhost:8123"
    elif variant == "cross_site":
        headers["HTTP_SEC_FETCH_SITE"] = "cross-site"
    elif variant == "unknown_session":
        sid = secrets.token_hex(32)
    elif variant == "altered_body":
        body += b" "
    elif variant == "revoked":
        adapter.revoke(sid)
    elif variant == "expired":
        adapter.sessions[sid].expires = time.monotonic()-1
    elif variant == "owner_override":
        body,proof = packet(sid,key,payload={"owner":B.owner})
    assert send(adapter,sid,body,proof,**headers) == (403,{"error":"D1_PRF_AUTHORIZATION_REFUSED"})
    assert row() == ("fresh",None,None)
    assert row(B) == ("fresh",None,None)


def test_http_roundtrip_and_replays(transport):
    adapter,key,sid = transport
    body,proof = packet(sid,key)
    code,e = send(adapter,sid,body,proof)
    assert code == 200
    assert send(adapter,sid,body,proof)[0] == 403
    assert send(adapter,sid,*packet(sid,key))[0] == 403
    assert send(adapter,sid,*packet(sid,key,"redeem",e)) == (200,{"redeemed":True})
    assert send(adapter,sid,*packet(sid,key,"redeem",e))[0] == 403
    assert send(adapter,sid,*packet(sid,key,"status",{"operationId":e["ticket"]["operationId"]})) == (200,{"state":"redeemed"})
    assert row()[0] == "redeemed"


def test_foreign_session_cannot_redeem(transport):
    adapter,key,sid = transport
    _,e = send(adapter,sid,*packet(sid,key))
    other = adapter.add_verified_fixture(B,key.public_key())
    assert send(adapter,other,*packet(other,key,"redeem",e))[0] == 403
    assert row()[0] == "reserved" and row(B)[0] == "fresh"


def test_duplicate_json_keys_refused(transport):
    adapter,key,sid = transport
    body = b'{"action":"status","action":"reserve","requestId":"' + b'a'*64 + b'","payload":{}}'
    r,s = decode_dss_signature(key.sign(proof_bytes(sid,body),ec.ECDSA(hashes.SHA256())))
    proof = (r.to_bytes(32,"big")+s.to_bytes(32,"big")).hex()
    assert send(adapter,sid,body,proof)[0] == 403
    assert row()[0] == "fresh"


class QuietHandler(WSGIRequestHandler):
    def log_message(self,*args):
        pass


@pytest.mark.parametrize("lost_ack",[False,True])
def test_browser_pg_transport(authority,lost_ack):
    _,issuer_key = authority
    proof_key = ec.generate_private_key(ec.SECP256R1())
    root = Path(__file__).resolve().parents[3]/"frontend/tool"
    adapter = None
    committed = threading.Event()
    modules = {"d1_prf_transport_candidate.mjs","d1_prf_provision_authority_candidate.mjs"}

    def app(environ,start_response):
        try:
            path = environ["PATH_INFO"]
            if path == "/":
                data = b"<!doctype html><meta charset=utf-8><title>synthetic candidate</title>"
                start_response("200 OK",[("Content-Type","text/html"),("Content-Length",str(len(data)))])
                return [data]
            if path[1:] in modules:
                data = (root/path[1:]).read_bytes()
                start_response("200 OK",[("Content-Type","text/javascript"),("Content-Length",str(len(data)))])
                return [data]
            req = WSGIRequest(environ)
            res = adapter(req)
            if lost_ack and res.status_code == 200 and json.loads(res.content) == {"redeemed":True}:
                committed.set()
                # Actual server commit completed; deliberately delay response.
                time.sleep(1.0)
            start_response(f"{res.status_code} {'OK' if res.status_code==200 else 'Forbidden'}",list(res.items()))
            return [res.content]
        finally:
            connections.close_all()

    server = make_server("127.0.0.1",0,app,handler_class=QuietHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    ctx = replace(A,binding=canonical(["AQIDBA","BQYHCA","127.0.0.1",origin]))
    seed(ctx)
    service = ProvisionAuthority(signing_key=issuer_key,origin=origin)
    adapter = CandidateTransport(service,origin)
    sid = adapter.add_verified_fixture(ctx,proof_key.public_key())
    pkcs8 = proof_key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    spki = issuer_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = browser.new_context(service_workers="block",locale="fr-FR",viewport={"width":390,"height":844})
                blocked = []
                def guard(route):
                    if route.request.url.startswith(origin+"/"):
                        route.continue_()
                    else:
                        blocked.append(route.request.url)
                        route.abort()
                context.route("**/*",guard)
                page = context.new_page()
                page.goto(origin)
                result = page.evaluate("""async p=>{
                  const raw=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
                  const {createProvisionTransport}=await import('/d1_prf_transport_candidate.mjs');
                  const {createSignedProvisioningAuthority}=await import('/d1_prf_provision_authority_candidate.mjs');
                  const proofKey=await crypto.subtle.importKey('pkcs8',raw(p.pkcs8),
                    {name:'ECDSA',namedCurve:'P-256'},false,['sign']);
                  const verificationKey=await crypto.subtle.importKey('spki',raw(p.spki),
                    {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
                  let pending=true;
                  const transport=createProvisionTransport({sessionId:p.sid,proofKey,isPending:()=>pending,
                    timeoutMs:5000});
                  const e=await transport.reserve();
                  const redeemTransport=createProvisionTransport({sessionId:p.sid,proofKey,isPending:()=>pending,
                    timeoutMs:p.lost?500:5000});
                  const auth=createSignedProvisioningAuthority({verificationKey,redeem:redeemTransport.redeem});
                  const refused=async fn=>{try{await fn();return false;}catch(_){return true;}};
                  const expected=p.expected;
                  const checks={};
                  checks.reserved=await transport.status(e.ticket.operationId)==='reserved';
                  checks.noSecondReserve=await refused(()=>transport.reserve());
                  checks.noBearerOnly=await fetch('/d1-provision-candidate',{method:'POST',
                    headers:{'Content-Type':'application/json','X-D1-Session':p.sid},
                    body:JSON.stringify({action:'reserve',requestId:'a'.repeat(64),payload:{}})}).then(r=>r.status===403);
                  if(p.lost){
                    checks.lostAckRefused=await refused(()=>auth.authorize(e,expected,()=>pending));
                    checks.statusRedeemed=await transport.status(e.ticket.operationId)==='redeemed';
                    checks.noRetryGrant=await refused(()=>auth.authorize(e,expected,()=>pending));
                  }else{
                    const grant=await auth.authorize(e,expected,()=>pending);
                    checks.grant=auth.consume(grant,expected.owner,expected.binding)?.operationId===e.ticket.operationId;
                    checks.statusRedeemed=await transport.status(e.ticket.operationId)==='redeemed';
                    checks.noRetryGrant=await refused(()=>auth.authorize(e,expected,()=>pending));
                  }
                  pending=false;
                  checks.cancelled=await refused(()=>transport.status(e.ticket.operationId));
                  return checks;
                }""",{"pkcs8":base64.b64encode(pkcs8).decode(),"spki":base64.b64encode(spki).decode(),
                      "sid":sid,"lost":lost_ack,"expected":ctx.fields(origin)})
                assert len(result)==7 and all(result.values()), result
                assert not blocked
            finally:
                browser.close()
        # sync_playwright owns an asyncio loop in this thread until exit.
        # Keep Django's async safety guard enabled and check the committed
        # database state only after that loop has been closed.
        assert row(ctx)[0] == "redeemed"
        if lost_ack:
            assert committed.is_set()
        print("D1_PRF_HTTP_BROWSER_PASS "+json.dumps({"lostAck":lost_ack,"checks":result}),flush=True)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

# E2E fixture: synthetic authenticator, real browser WebCrypto/IndexedDB and
# real HTTP/PG16. Never claim that this qualifies a physical authenticator.
@pytest.mark.parametrize("engine",["chromium","webkit"])
@pytest.mark.parametrize("scenario",["normal","lost_ack","cancel_after_redeem"])
def test_browser_pg_vault_e2e(authority,engine,scenario):
    _,issuer_key = authority
    proof_key = ec.generate_private_key(ec.SECP256R1())
    authenticator = ec.generate_private_key(ec.SECP256R1())
    root = Path(__file__).resolve().parents[3]/"frontend/tool"
    modules = {"d1_prf_transport_candidate.mjs","d1_prf_provision_authority_candidate.mjs",
        "d1_prf_guard_bridge_candidate.mjs","d1_prf_counter_candidate.mjs",
        "d1_prf_possession_candidate.mjs","d1_prf_vault_candidate.mjs",
        "d1_prf_lifecycle_candidate.mjs","d1_admission_store.mjs",
        "d1_prf_http_vault_probe.mjs"}
    adapter = None
    committed = threading.Event()

    def app(environ,start_response):
        try:
            path = environ["PATH_INFO"]
            if path == "/" or path[1:] in modules:
                data = (b"<!doctype html><meta charset=utf-8><title>synthetic E2E</title>"
                        if path == "/" else (root/path[1:]).read_bytes())
                start_response("200 OK",[("Content-Type","text/html" if path=="/" else "text/javascript"),
                    ("Content-Length",str(len(data))),("Cache-Control","no-store")])
                return [data]
            res = adapter(WSGIRequest(environ))
            if res.status_code == 200 and json.loads(res.content) == {"redeemed":True}:
                committed.set()
                if scenario=="lost_ack":
                    time.sleep(1.0)
            start_response(f"{res.status_code} {'OK' if res.status_code==200 else 'Forbidden'}",list(res.items()))
            return [res.content]
        finally:
            connections.close_all()

    def spki(key):
        return key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    def private(key):
        return base64.b64encode(key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode()
    server = make_server("127.0.0.1",0,app,handler_class=QuietHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    credential = {"version":1,"credentialId":"DQ4PEA",
        "publicKeySpki":base64.urlsafe_b64encode(spki(authenticator)).decode().rstrip("="),
        "rpId":"127.0.0.1","origin":origin,"signCount":0}
    ctx = replace(A,binding=canonical([credential[k] for k in
        ("credentialId","publicKeySpki","rpId","origin")]))
    seed(ctx)
    adapter = CandidateTransport(ProvisionAuthority(signing_key=issuer_key,origin=origin),origin)
    sid = adapter.add_verified_fixture(ctx,proof_key.public_key())
    payload = {"credential":credential,"expected":ctx.fields(origin),"scenario":scenario,
        "sid":sid,"proof":private(proof_key),"authenticator":private(authenticator),
        "issuer":base64.b64encode(spki(issuer_key)).decode()}
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    blocked=[]
    try:
        with tempfile.TemporaryDirectory(prefix="d1-e2e-") as profile, sync_playwright() as pw:
            browser_type = getattr(pw,engine)
            def launch():
                c = browser_type.launch_persistent_context(profile,headless=True,
                    locale="fr-FR",viewport={"width":390,"height":844},service_workers="block")
                def guard(route):
                    url=route.request.url
                    if url==origin+"/" or url in {origin+"/"+m for m in modules} or (
                            url==origin+PATH and route.request.method=="POST"):
                        route.continue_()
                    else:
                        blocked.append(url.split("?")[0])
                        route.abort()
                c.route("**/*",guard)
                c.route_web_socket("**/*",lambda ws: (blocked.append("websocket"),ws.close()))
                p = c.pages[0] if c.pages else c.new_page()
                p.goto(origin)
                return c,p
            browser,page=launch()
            try:
                initial=page.evaluate("""async p=>(await import('/d1_prf_http_vault_probe.mjs')).initial(p)""",payload)
                assert all(v is True for v in initial["checks"].values()),initial
                assert len(initial["checks"]) == (9 if scenario=="normal" else 7),initial
            finally:
                browser.close()
            browser,page=launch()
            try:
                after=page.evaluate("""async p=>(await import('/d1_prf_http_vault_probe.mjs')).restart(p)""",
                    {**payload,"operationId":initial["operationId"]})
                assert all(v is True for v in after.values()),after
                assert len(after)==(9 if scenario=="normal" else 5),after
            finally:
                browser.close()
        assert not blocked,blocked
        assert committed.is_set() and row(ctx)[0]=="redeemed"
        print("D1_PRF_HTTP_VAULT_E2E_PASS "+json.dumps({"engine":engine,"scenario":scenario,
            "initial":initial["checks"],"restart":after}),flush=True)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()



# P2a: server-side assertion verification plus HTTPS-only request boundary.
# Signed synthetic assertions, RequestFactory HTTPS metadata (not actual TLS).
from hashlib import sha256
from core.d1_prf_authority_candidate import Refused
from core.d1_prf_https_qualification_candidate import (
    HttpsQualificationAuthority, HttpsQualificationTransport, ORIGIN as HTTPS_ORIGIN,
    RP_ID, b64,
)


@pytest.fixture
def https_candidate(authority, settings):
    # RequestFactory still enforces Django's ALLOWED_HOSTS through get_host().
    # Scope the exact synthetic hostname to this fixture; no product settings change.
    settings.ALLOWED_HOSTS = [*settings.ALLOWED_HOSTS, RP_ID]
    request = RequestFactory().generic("POST", PATH, b"{}", secure=True, HTTP_HOST=RP_ID)
    assert request.get_host() == RP_ID and request.is_secure()
    _, issuer = authority
    auth_key = ec.generate_private_key(ec.SECP256R1())
    proof_key = ec.generate_private_key(ec.SECP256R1())
    spki = auth_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ctx = replace(A, binding=canonical([b64(b"test-credential"), b64(spki), RP_ID, HTTPS_ORIGIN]))
    seed(ctx)
    adapter = HttpsQualificationTransport(HttpsQualificationAuthority(signing_key=issuer, origin=HTTPS_ORIGIN))
    return adapter, ctx, auth_key, proof_key


def signed_assertion(challenge, auth_key, **changes):
    c = {"type":"webauthn.get", "challenge":challenge, "origin":HTTPS_ORIGIN, "crossOrigin":False}
    c.update(changes.get("client", {}))
    client = json.dumps(c,separators=(",",":")).encode()
    data = sha256(changes.get("rp",RP_ID).encode()).digest() + bytes([changes.get("flags",5)]) + bytes(4)
    signature = auth_key.sign(data + sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
    return dict(credential_id=changes.get("credential_id",b64(b"test-credential")),
                client_data=client, authenticator_data=data, signature=signature)


def https_send(adapter, sid, body, proof, **overrides):
    headers = dict(secure=True, HTTP_HOST=RP_ID, HTTP_ORIGIN=HTTPS_ORIGIN)
    headers.update(overrides)
    return send(adapter,sid,body,proof,**headers)


def test_https_verified_session_roundtrip(https_candidate):
    adapter,ctx,auth,proof = https_candidate
    challenge = adapter.begin(ctx,proof.public_key())
    sid = adapter.finish(challenge,**signed_assertion(challenge,auth))
    with pytest.raises(Refused):
        adapter.finish(challenge,**signed_assertion(challenge,auth))
    with pytest.raises(Refused):
        adapter.add_verified_fixture(ctx,proof.public_key())
    assert https_send(adapter,sid,*packet(sid,ec.generate_private_key(ec.SECP256R1())))[0] == 403
    code,e = https_send(adapter,sid,*packet(sid,proof))
    assert code == 200
    assert https_send(adapter,sid,*packet(sid,proof,"redeem",e)) == (200,{"redeemed":True})
    assert https_send(adapter,sid,*packet(sid,proof))[0] == 403
    assert row(ctx)[0] == "redeemed"
    restarted = HttpsQualificationTransport(adapter.authority)
    assert https_send(restarted,sid,*packet(sid,proof))[0] == 403
    c2 = restarted.begin(ctx,proof.public_key())
    s2 = restarted.finish(c2,**signed_assertion(c2,auth))
    assert https_send(restarted,s2,*packet(s2,proof))[0] == 403
    assert row(ctx)[0] == "redeemed"


@pytest.mark.parametrize("variant",["wrong_origin","wrong_rp","wrong_challenge","cross_origin",
    "missing_uv","missing_up","invalid_backup","wrong_credential","wrong_signer","expired",
    "wrong_type","top_origin"])
def test_https_assertion_refusal_consumes_challenge(https_candidate,variant):
    adapter,ctx,auth,proof = https_candidate
    challenge = adapter.begin(ctx,proof.public_key())
    changes = {}
    if variant == "wrong_origin": changes["client"]={"origin":"https://foreign.test"}
    elif variant == "wrong_rp": changes["rp"]="foreign.test"
    elif variant == "wrong_challenge": changes["client"]={"challenge":b64(bytes(32))}
    elif variant == "cross_origin": changes["client"]={"crossOrigin":True}
    elif variant == "missing_uv": changes["flags"]=1
    elif variant == "missing_up": changes["flags"]=4
    elif variant == "invalid_backup": changes["flags"]=21
    elif variant == "wrong_credential": changes["credential_id"]=b64(b"foreign")
    elif variant == "wrong_signer": auth=ec.generate_private_key(ec.SECP256R1())
    elif variant == "expired":
        _,*rest=adapter.challenges[challenge]
        adapter.challenges[challenge]=(time.monotonic()-1,*rest)
    elif variant == "wrong_type": changes["client"]={"type":"webauthn.create"}
    elif variant == "top_origin": changes["client"]={"topOrigin":"https://foreign.test"}
    with pytest.raises(Refused):
        adapter.finish(challenge,**signed_assertion(challenge,auth,**changes))
    assert not adapter.sessions and challenge not in adapter.challenges
    assert row(ctx) == ("fresh",None,None)


@pytest.mark.parametrize("overrides",[
    {"secure":False}, {"secure":False,"HTTP_X_FORWARDED_PROTO":"https"},
    {"HTTP_FORWARDED":"proto=https"}, {"HTTP_X_FORWARDED_HOST":RP_ID},
    {"HTTP_ORIGIN":"https://foreign.test"}, {"HTTP_HOST":"foreign.test"},
    {"HTTP_SEC_FETCH_SITE":"cross-site"},
])
def test_https_transport_boundary(https_candidate,overrides):
    adapter,ctx,auth,proof = https_candidate
    c = adapter.begin(ctx,proof.public_key())
    sid = adapter.finish(c,**signed_assertion(c,auth))
    assert https_send(adapter,sid,*packet(sid,proof),**overrides) == (403,{"error":"D1_PRF_AUTHORIZATION_REFUSED"})
    assert row(ctx) == ("fresh",None,None)


@pytest.mark.parametrize("origin",["http://127.0.0.1:8123","https://foreign.test",
    HTTPS_ORIGIN+"/", HTTPS_ORIGIN+":443", HTTPS_ORIGIN+"?x=1"])
def test_https_authority_origin_exact(authority,origin):
    _,issuer=authority
    with pytest.raises(Refused):
        HttpsQualificationAuthority(signing_key=issuer,origin=origin)


def test_loopback_authority_still_rejects_https(authority):
    _,issuer=authority
    with pytest.raises(Refused):
        ProvisionAuthority(signing_key=issuer,origin=HTTPS_ORIGIN)


def test_https_authority_rejects_other_db(https_candidate,monkeypatch):
    from django.db import connection
    adapter,ctx,_,_=https_candidate
    with monkeypatch.context() as patch:
        patch.setitem(connection.settings_dict,"NAME","untrusted_db")
        with pytest.raises(Refused):
            adapter.authority.reserve(ctx)
    assert row(ctx) == ("fresh",None,None)



# P2b.1: real TLS sockets, pinned ephemeral test certificate and PG16.
# No DNS override, public bind, browser, or physical authenticator claim.
import http.client
import socket
import ssl
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID


class LocalQualificationHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class QualificationTLSHandler(QuietHandler):
    def get_environ(self):
        env = super().get_environ()
        assert isinstance(self.connection, ssl.SSLSocket)
        assert self.connection.version() in ("TLSv1.2", "TLSv1.3")
        env["HTTPS"] = "on"
        return env


@pytest.fixture
def tls_candidate(https_candidate, tmp_path):
    adapter, ctx, auth, proof = https_candidate
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, RP_ID)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=2)).not_valid_after(now+timedelta(minutes=20))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(RP_ID)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True,path_length=0), critical=True)
            .sign(key,hashes.SHA256()))
    cert_file, key_file = tmp_path/"cert.pem", tmp_path/"key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.touch(mode=0o600)
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.minimum_version = ssl.TLSVersion.TLSv1_2
    server_tls.load_cert_chain(str(cert_file),str(key_file))
    trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trusted.minimum_version = ssl.TLSVersion.TLSv1_2
    trusted.load_verify_locations(cafile=str(cert_file))
    assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED
    committed, release = threading.Event(), threading.Event()
    state = {"drop":False,"requests":0}
    def app(environ,start_response):
        try:
            state["requests"] += 1
            req = WSGIRequest(environ)
            res = adapter(req)
            if state["drop"] and res.status_code == 200 and json.loads(res.content) == {"redeemed":True}:
                committed.set()
                # Commit happened; withhold response until client times out.
                assert release.wait(8)
            start_response(f"{res.status_code} {'OK' if res.status_code==200 else 'Forbidden'}",list(res.items()))
            return [res.content]
        finally:
            connections.close_all()
    server = make_server("127.0.0.1",0,app,handler_class=QualificationTLSHandler)
    server.socket = server_tls.wrap_socket(server.socket,server_side=True)
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        yield adapter,ctx,auth,proof,server.server_port,trusted,state,committed,release
    finally:
        release.set()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        assert not thread.is_alive()


def tls_packet(port, tls, sid, body, proof, *, timeout=5, host=RP_ID):
    conn = LocalQualificationHTTPS(host,port,context=tls,timeout=timeout)
    try:
        conn.connect()
        assert conn.sock.version() in ("TLSv1.2","TLSv1.3")
        conn.request("POST",PATH,body,headers={
            "Host":RP_ID,"Origin":HTTPS_ORIGIN,"Sec-Fetch-Site":"same-origin",
            "Content-Type":"application/json","X-D1-Session":sid,"X-D1-Proof":proof,
        })
        response = conn.getresponse()
        assert response.getheader("Cache-Control") == "no-store"
        assert response.getheader("Access-Control-Allow-Origin") is None
        return response.status,json.loads(response.read())
    finally:
        conn.close()


@pytest.mark.parametrize("lost_ack",[False,True])
def test_https_actual_tls_pg_roundtrip(tls_candidate,lost_ack):
    adapter,ctx,auth,proof,port,tls,state,committed,release = tls_candidate
    challenge = adapter.begin(ctx,proof.public_key())
    sid = adapter.finish(challenge,**signed_assertion(challenge,auth))
    def send_tls(action="reserve",payload=None,**kwargs):
        return tls_packet(port,tls,sid,*packet(sid,proof,action,payload),**kwargs)
    code,e = send_tls()
    assert code == 200 and row(ctx)[0] == "reserved"
    assert send_tls()[0] == 403
    assert send_tls("status",{"operationId":e["ticket"]["operationId"]}) == (200,{"state":"reserved"})
    if lost_ack:
        state["drop"] = True
        try:
            with pytest.raises(TimeoutError):
                send_tls("redeem",e,timeout=2)
            assert committed.wait(5)
            assert row(ctx)[0] == "redeemed"
        finally:
            release.set()
    else:
        assert send_tls("redeem",e) == (200,{"redeemed":True})
    assert send_tls("status",{"operationId":e["ticket"]["operationId"]}) == (200,{"state":"redeemed"})
    assert send_tls("redeem",e)[0] == 403
    assert send_tls()[0] == 403
    assert row(ctx)[0] == "redeemed"
    print("D1_PRF_TLS_PG_PASS "+json.dumps({"lostAck":lost_ack,"verifiedTLS":True,
        "terminalRedemption":True,"noReissue":True}),flush=True)


@pytest.mark.parametrize("variant",["untrusted_certificate","wrong_hostname"])
def test_https_actual_tls_rejects_peer(tls_candidate,variant):
    adapter,ctx,auth,proof,port,tls,state,_,_ = tls_candidate
    c = adapter.begin(ctx,proof.public_key())
    sid = adapter.finish(c,**signed_assertion(c,auth))
    if variant == "untrusted_certificate":
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    host = "foreign.test" if variant == "wrong_hostname" else RP_ID
    assert tls.check_hostname and tls.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_packet(port,tls,sid,*packet(sid,proof),host=host)
    assert state["requests"] == 0 and row(ctx) == ("fresh",None,None)



# Physical E2E preparation: durable challenge and proof-bound session across
# independent service instances; real PG16, synthetic signed assertions only.
from core.d1_physical_lab_candidate import DurablePhysicalSessions, SESSION_TABLE, check_lab_database


@pytest.fixture
def durable_physical_session(https_candidate):
    from django.db import connection
    adapter,ctx,auth,proof=https_candidate
    def guard():
        assert connection.vendor=="postgresql"
        assert connection.settings_dict["NAME"]=="test_iamina_phase1_ci"
        assert connection.settings_dict["HOST"]=="127.0.0.1"
    guard()
    with connection.cursor() as cur:
        cur.execute(f"""CREATE TABLE {SESSION_TABLE} (
            owner bigint PRIMARY KEY CHECK(owner IN (900001,900002)),
            context text NOT NULL, pending text, session text,
            sign_count bigint NOT NULL DEFAULT 0 CHECK(sign_count BETWEEN 0 AND 4294967295)
        )""")
        cur.execute(f"INSERT INTO {SESSION_TABLE}(owner,context) VALUES(%s,%s)",[ctx.owner,canonical(ctx.fields(HTTPS_ORIGIN))])
    try:
        yield guard,adapter,ctx,auth,proof
    finally:
        with connection.cursor() as cur:
            cur.execute(f"DROP TABLE {SESSION_TABLE}")


def durable_begin(service,ctx,proof):
    spki=b64(proof.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    return service.begin(ctx.owner,spki)["challenge"]


def durable_finish(service,ctx,c,auth,**changes):
    a=signed_assertion(c,auth,**changes)
    return service.finish(ctx.owner,c,a["credential_id"],a["client_data"],a["authenticator_data"],a["signature"])["sessionId"]


def test_physical_session_survives_worker_replacement(durable_physical_session):
    guard,adapter,ctx,auth,proof=durable_physical_session
    a=DurablePhysicalSessions(HTTPS_ORIGIN,guard)
    c=durable_begin(a,ctx,proof)
    b=DurablePhysicalSessions(HTTPS_ORIGIN,guard)
    sid=durable_finish(b,ctx,c,auth)
    with pytest.raises(Refused):
        durable_finish(a,ctx,c,auth)
    body,sig=packet(sid,proof)
    verified,data=a.claim(ctx.owner,sid,body,bytes.fromhex(sig))
    assert verified==ctx and data["action"]=="reserve"
    e=adapter.authority.reserve(verified)
    with pytest.raises(Refused):
        b.claim(ctx.owner,sid,body,bytes.fromhex(sig))
    wrong_body,wrong_sig=packet(sid,ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(Refused):
        b.claim(ctx.owner,sid,wrong_body,bytes.fromhex(wrong_sig))
    assert row(ctx)[0]=="reserved"
    body,sig=packet(sid,proof,"redeem",{"ticket":e["ticket"],"signature":e["signature"].hex()})
    verified,data=b.claim(ctx.owner,sid,body,bytes.fromhex(sig))
    assert adapter.authority.redeem(verified,data["payload"]["ticket"],bytes.fromhex(data["payload"]["signature"]))
    c2=durable_begin(a,ctx,proof)
    sid2=durable_finish(b,ctx,c2,auth)
    body,sig=packet(sid,proof)
    with pytest.raises(Refused):
        a.claim(ctx.owner,sid,body,bytes.fromhex(sig))
    body,sig=packet(sid2,proof)
    verified,_=b.claim(ctx.owner,sid2,body,bytes.fromhex(sig))
    with pytest.raises(Refused):
        adapter.authority.reserve(verified)
    assert row(ctx)[0]=="redeemed"


def test_physical_invalid_assertion_consumed_across_workers(durable_physical_session):
    guard,_,ctx,auth,proof=durable_physical_session
    a=DurablePhysicalSessions(HTTPS_ORIGIN,guard)
    c=durable_begin(a,ctx,proof)
    with pytest.raises(Refused):
        durable_finish(a,ctx,c,auth,flags=1)
    b=DurablePhysicalSessions(HTTPS_ORIGIN,guard)
    with pytest.raises(Refused):
        durable_finish(b,ctx,c,auth)
    assert row(ctx)==("fresh",None,None)
    c2=durable_begin(b,ctx,proof)
    assert durable_finish(a,ctx,c2,auth)


def test_physical_guard_refuses_ci_database(durable_physical_session):
    with pytest.raises(Refused):
        check_lab_database()


# Physical same-origin composition: the operator explicitly authorizes an
# unbound synthetic slot; signed assertion proves possession, no attestation.
from core.d1_physical_lab_web import PhysicalLab, OWNER, MODULES, STATIC, post_body


def test_physical_hosted_composition(durable_physical_session,settings):
    from django.db import connection
    from core.d1_prf_authority_candidate import TABLE
    guard,adapter,ctx,auth,proof=durable_physical_session
    with connection.cursor() as cur:
        cur.execute(f"UPDATE {SESSION_TABLE} SET context='' WHERE owner=%s",[OWNER])
        cur.execute(f"UPDATE {TABLE} SET state='unknown',binding='' WHERE owner=%s",[OWNER])
    lab=PhysicalLab(HTTPS_ORIGIN,adapter.authority._key,guard)
    q=lab.enroll_begin()
    c=json.dumps({"type":"webauthn.create","origin":HTTPS_ORIGIN,"challenge":q["create"]}).encode()
    cid=b"test-credential"
    ca=sha256(RP_ID.encode()).digest()+bytes([0x45])+bytes(4)+bytes(16)+len(cid).to_bytes(2,"big")+cid+b"\xa1"
    a=signed_assertion(q["prove"],auth)
    spki=b64(auth.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    payload=dict(challenge=q["create"],credentialId=b64(cid),publicKeySpki=spki,creationClient=b64(c),
        creationAuth=b64(ca),assertionClient=b64(a["client_data"]),assertionAuth=b64(a["authenticator_data"]),
        signature=b64(a["signature"]))
    assert lab.enroll_finish(payload)=={"enrolled":True,"signCount":0}
    with pytest.raises(Refused):
        lab.enroll_finish(payload)
    with pytest.raises(Refused):
        lab.enroll_begin()
    ch=durable_begin(lab.sessions,ctx,proof)
    sid=durable_finish(lab.sessions,ctx,ch,auth)
    body,sig=packet(sid,proof)
    e=lab.sessions.claim(OWNER,sid,body,bytes.fromhex(sig),dispatch=lab.dispatch)
    assert row(ctx)[0]=="reserved"
    with pytest.raises(Refused):
        lab.sessions.claim(OWNER,sid,body,bytes.fromhex(sig),dispatch=lab.dispatch)
    body,sig=packet(sid,proof,"redeem",e)
    assert lab.sessions.claim(OWNER,sid,body,bytes.fromhex(sig),dispatch=lab.dispatch)=={"redeemed":True}
    body,sig=packet(sid,proof)
    with pytest.raises(Refused):
        lab.sessions.claim(OWNER,sid,body,bytes.fromhex(sig),dispatch=lab.dispatch)
    assert row(ctx)[0]=="redeemed"


@pytest.mark.parametrize("variant",["operator","origin","host","scheme","cross_site","forwarded_host","forwarded_proto"])
def test_physical_http_boundary(settings,variant):
    settings.PHYSICAL_LAB_ORIGIN=HTTPS_ORIGIN
    settings.PHYSICAL_LAB_OPERATOR_HASH=sha256(b"a"*64).hexdigest()
    settings.ALLOWED_HOSTS=[RP_ID]
    headers=dict(secure=True,HTTP_HOST=RP_ID,HTTP_ORIGIN=HTTPS_ORIGIN,
        HTTP_SEC_FETCH_SITE="same-origin",HTTP_X_D1_OPERATOR="a"*64,
        HTTP_X_FORWARDED_HOST=RP_ID,HTTP_X_FORWARDED_PROTO="https")
    assert post_body(RequestFactory().generic("POST","/physical/begin",b"{}",
        content_type="application/json",**headers))==b"{}"
    key,val={"operator":("HTTP_X_D1_OPERATOR","b"*64),"origin":("HTTP_ORIGIN","https://foreign.test"),
        "host":("HTTP_HOST","foreign.test"),"scheme":("secure",False),
        "cross_site":("HTTP_SEC_FETCH_SITE","cross-site"),
        "forwarded_host":("HTTP_X_FORWARDED_HOST","foreign.test"),
        "forwarded_proto":("HTTP_X_FORWARDED_PROTO","https,http")}[variant]
    headers[key]=val
    with pytest.raises(Exception):
        post_body(RequestFactory().generic("POST","/physical/begin",b"{}",
            content_type="application/json",**headers))


def test_physical_packaged_candidate_modules_exact():
    root=Path(__file__).resolve().parents[3]/"frontend/tool"
    for name in MODULES-{"physical.mjs","physical_transport.mjs"}:
        assert (STATIC/name).read_bytes()==(root/name).read_bytes()


@pytest.mark.parametrize("variant",["valid","production","wrong_project","wrong_host","wrong_role","tls_unverified"])
def test_physical_preview_settings_gate(monkeypatch,variant):
    import runpy
    host="iamina-d1-6-safari-django-preview-20261113-84yi058tz.vercel.app"
    config={
        "VERCEL":"1","VERCEL_ENV":"preview","VERCEL_PROJECT_ID":"prj_hnlWE6QdXtWvYVfwe2JVAqIKPUiP",
        "IAMINA_PHYSICAL_E2E":"synthetic-v1","IAMINA_D1_SAFARI_LAB_ONLY":"synthetic-preview-v1",
        "IAMINA_ENV":"development","VERCEL_URL":host,"IAMINA_PHYSICAL_OPERATOR_SHA256":"a"*64,
        "IAMINA_PHYSICAL_ISSUER_PKCS8":"a"*180,"SECRET_KEY":"test-only-secret-"+"x"*32,
        "DATABASE_URL":"postgresql://d1_safari_runtime:unused@ep-frosty-tooth-b921hjv8-pooler.c-7.eu-central-1.aws.neon.tech/iamina925_empty?sslmode=verify-full&sslrootcert=system",
    }
    if variant=="production":config["VERCEL_ENV"]="production"
    elif variant=="wrong_project":config["VERCEL_PROJECT_ID"]="wrong"
    elif variant=="wrong_host":config["VERCEL_URL"]="iamina-certified.vercel.app"
    elif variant=="wrong_role":config["DATABASE_URL"]=config["DATABASE_URL"].replace("d1_safari_runtime","iamina925_empty_owner")
    elif variant=="tls_unverified":config["DATABASE_URL"]=config["DATABASE_URL"].replace("verify-full","require")
    for k,v in config.items():monkeypatch.setenv(k,v)
    if variant=="valid":
        module=runpy.run_module("amina.physical_lab_settings")
        assert module["ALLOWED_HOSTS"]==[host]
        assert module["ROOT_URLCONF"]=="core.d1_physical_lab_web" and module["INSTALLED_APPS"]==[]
        assert module["DATABASES"]["default"]["OPTIONS"]["sslmode"]=="verify-full"
    else:
        with pytest.raises(ValueError,match="Physical lab configuration refused"):
            runpy.run_module("amina.physical_lab_settings")
