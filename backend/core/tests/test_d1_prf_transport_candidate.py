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
