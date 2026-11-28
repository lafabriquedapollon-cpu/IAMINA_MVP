"""Operator-only physical WebAuthn/PRF qualification, never product URLs.

Enrollment is explicitly authorized by a high-entropy operator capability
and independently initialized synthetic inventory. No attestation claim.
A native assertion proves possession of the enrolled key, not physical
exclusive device binding or the client PRF result. No PRF bytes are accepted.
"""
import hashlib
import json
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from core.d1_physical_lab_candidate import DurablePhysicalSessions, SESSION_TABLE, check_lab_database
from core.d1_prf_authority_candidate import ProvisionAuthority, Refused, VerifiedContext, TABLE, canonical, require, hex_id
from core.d1_prf_https_qualification_candidate import b64, decode
from core.d1_prf_transport_candidate import exact, no_duplicates

OWNER = 900001
STATIC = Path(__file__).resolve().parent / "physical_lab_static"
MODULES = frozenset((
    "physical.mjs", "physical_transport.mjs",
    "d1_prf_guard_bridge_candidate.mjs", "d1_prf_counter_candidate.mjs",
    "d1_prf_possession_candidate.mjs", "d1_prf_vault_candidate.mjs",
    "d1_prf_lifecycle_candidate.mjs", "d1_admission_store.mjs",
    "d1_prf_provision_authority_candidate.mjs",
))
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
       "form-action 'none'; object-src 'none'")


def protected(response):
    response["Cache-Control"] = "no-store"
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = CSP
    response["Referrer-Policy"] = "no-referrer"
    response["X-Frame-Options"] = "DENY"
    response["Permissions-Policy"] = "publickey-credentials-get=(self), publickey-credentials-create=(self)"
    return response


def boundary(request):
    require(request.is_secure() and request.get_host() == settings.PHYSICAL_LAB_ORIGIN[8:])
    # Vercel includes x-forwarded-host at its TLS boundary. Never use it
    # to select an origin: accept only an exact redundant match.
    require("HTTP_FORWARDED" not in request.META
            and request.META.get("HTTP_X_FORWARDED_HOST",request.get_host())==request.get_host()
            and request.META.get("HTTP_X_FORWARDED_PROTO","https")=="https")


def operator(request):
    token = request.headers.get("X-D1-Operator", "")
    require(hex_id(token) and secrets.compare_digest(
        hashlib.sha256(token.encode("ascii")).hexdigest(), settings.PHYSICAL_LAB_OPERATOR_HASH))


def post_body(request):
    boundary(request)
    require(request.method == "POST" and request.headers.get("Origin") == settings.PHYSICAL_LAB_ORIGIN
            and request.headers.get("Sec-Fetch-Site") == "same-origin"
            and request.content_type == "application/json")
    operator(request)
    length = request.META.get("CONTENT_LENGTH","")
    require(length.isascii() and length.isdecimal() and 0 < int(length) <= 32768)
    body = request.body
    require(len(body) == int(length))
    return body


def response_or_refusal(fn):
    try:
        return protected(JsonResponse(fn()))
    except Exception:
        # Never log raw credentials, request bodies, operator secrets or DB errors.
        return protected(JsonResponse({"error":"D1_PHYSICAL_LAB_REFUSED"},status=403))


class LockedAuthority(ProvisionAuthority):
    """Authority invoked only within the durable session dispatch transaction."""
    def __init__(self, key, origin):
        require(isinstance(key,ec.EllipticCurvePrivateKey) and isinstance(key.curve,ec.SECP256R1))
        self._key, self._origin = key, origin

    def _locked(self, owner, work):
        require(owner == OWNER and connection.in_atomic_block)
        with connection.cursor() as cur:
            cur.execute(f"SELECT state,binding,ticket,signature FROM {TABLE} WHERE owner=%s FOR UPDATE",[owner])
            row = cur.fetchone()
            require(row is not None)
            cur.execute("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            return work(cur,row,cur.fetchone()[0])


class PhysicalLab:
    def __init__(self, origin, issuer, guard):
        self.sessions = DurablePhysicalSessions(origin,guard)
        self.issuer = issuer
        self.authority = LockedAuthority(issuer,origin)

    def issuer_spki(self):
        return b64(self.issuer.public_key().public_bytes(
            serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))

    def enroll_begin(self):
        # Explicit preseed, never infer freshness from missing local storage.
        create, prove = b64(secrets.token_bytes(32)), b64(secrets.token_bytes(32))
        def work(cur,row,now):
            require(row[0] == "" and row[2] is None)
            require(row[1] is None or json.loads(row[1])["expires"] <= now)
            cur.execute(f"SELECT state,binding,ticket,signature FROM {TABLE} WHERE owner=%s FOR UPDATE",[OWNER])
            require(cur.fetchone() == ("unknown","",None,None))
            p = canonical({"create":create,"prove":prove,"expires":now+120000})
            cur.execute(f"UPDATE {SESSION_TABLE} SET pending=%s WHERE owner=%s",[p,OWNER])
            return {"create":create,"prove":prove}
        return self.sessions._locked(OWNER,work)

    def enroll_finish(self,data):
        fields=("challenge","credentialId","publicKeySpki","creationClient","creationAuth",
                "assertionClient","assertionAuth","signature")
        require(exact(data,fields))
        def work(cur,row,now):
            p=json.loads(row[1]) if row[1] else None
            require(row[0]=="" and row[2] is None and p is not None and p.get("create")==data["challenge"])
            cur.execute(f"UPDATE {SESSION_TABLE} SET pending=NULL WHERE owner=%s",[OWNER])
            try:
                require(now < p["expires"])
                cid=decode(data["credentialId"])
                require(0 < len(cid) <= 1024)
                key=self.sessions._public_key(data["publicKeySpki"])
                rp=self.sessions.rp_id
                origin=self.sessions.origin
                rp_hash=hashlib.sha256(rp.encode()).digest()
                def client(raw,typ,challenge):
                    b=decode(raw)
                    v=json.loads(b.decode("utf-8"),object_pairs_hook=no_duplicates)
                    require(type(v) is dict and v.get("type")==typ and v.get("challenge")==challenge
                            and v.get("origin")==origin and v.get("crossOrigin",False) is False
                            and "topOrigin" not in v)
                    return b
                client(data["creationClient"],"webauthn.create",p["create"])
                ca=decode(data["creationAuth"])
                require(55 <= len(ca) <= 4096 and secrets.compare_digest(ca[:32],rp_hash))
                require(ca[32]&0x45==0x45 and (not ca[32]&0x10 or ca[32]&8))
                n=int.from_bytes(ca[53:55],"big")
                require(n==len(cid) and ca[55:55+n]==cid and len(ca)>55+n)
                # No attestation verification: explicitly operator-authorized
                # key enrollment, with subsequent signed possession challenge.
                ac=client(data["assertionClient"],"webauthn.get",p["prove"])
                aa=decode(data["assertionAuth"])
                sig=decode(data["signature"])
                require(37<=len(aa)<=4096 and 0<len(sig)<=80 and secrets.compare_digest(aa[:32],rp_hash))
                flags=aa[32]
                require(flags&5==5 and not flags&0x40 and (not flags&0x10 or flags&8)
                        and (len(aa)>37 if flags&0x80 else len(aa)==37))
                key.verify(sig,aa+hashlib.sha256(ac).digest(),ec.ECDSA(hashes.SHA256()))
                count=int.from_bytes(aa[33:37],"big")
                first=int.from_bytes(ca[33:37],"big")
                require((first==0 and count==0) or count>first)
                ctx=VerifiedContext(OWNER,canonical([data["credentialId"],data["publicKeySpki"],rp,origin]),
                                    1,1,secrets.token_hex(32))
                ctx.fields(origin)
            except Exception:
                return None
            cur.execute(f"SELECT state,binding,ticket,signature FROM {TABLE} WHERE owner=%s FOR UPDATE",[OWNER])
            require(cur.fetchone()==("unknown","",None,None))
            cur.execute(f"UPDATE {TABLE} SET state='fresh',binding=%s WHERE owner=%s",[ctx.binding,OWNER])
            cur.execute(f"UPDATE {SESSION_TABLE} SET context=%s,sign_count=%s WHERE owner=%s",
                        [canonical(ctx.fields(origin)),count,OWNER])
            return {"enrolled":True,"signCount":count}
        result=self.sessions._locked(OWNER,work)
        require(result is not None)
        return result

    def dispatch(self,ctx,data):
        p=data["payload"]
        if data["action"]=="reserve":
            require(exact(p,()))
            e=self.authority.reserve(ctx)
            return {"ticket":e["ticket"],"signature":e["signature"].hex()}
        if data["action"]=="redeem":
            require(exact(p,("ticket","signature")) and type(p["signature"]) is str
                    and re.fullmatch(r"[0-9a-f]{128}",p["signature"]))
            require(self.authority.redeem(ctx,p["ticket"],bytes.fromhex(p["signature"])))
            return {"redeemed":True}
        if data["action"]=="status":
            require(exact(p,("operationId",)))
            return {"state":self.authority.status(ctx,p["operationId"])}
        raise Refused("D1_PHYSICAL_LAB_REFUSED")

    def call(self,action,data,body,request):
        if action=="enroll-begin":
            require(exact(data,()))
            return self.enroll_begin()
        if action=="enroll-finish":
            return self.enroll_finish(data)
        if action=="begin":
            require(exact(data,("proofSpki",)))
            return {**self.sessions.begin(OWNER,data["proofSpki"]),"issuerSpki":self.issuer_spki()}
        if action=="finish":
            require(exact(data,("challenge","credentialId","clientData","authData","signature")))
            return self.sessions.finish(OWNER,data["challenge"],data["credentialId"],decode(data["clientData"]),
                                        decode(data["authData"]),decode(data["signature"]))
        if action=="provision":
            sid=request.headers.get("X-D1-Session","")
            sig=request.headers.get("X-D1-Proof","")
            require(re.fullmatch(r"[0-9a-f]{128}",sig))
            return self.sessions.claim(OWNER,sid,body,bytes.fromhex(sig),dispatch=self.dispatch)
        raise Refused("D1_PHYSICAL_LAB_REFUSED")


def lab():
    issuer=serialization.load_der_private_key(decode(settings.PHYSICAL_LAB_ISSUER),password=None)
    return PhysicalLab(settings.PHYSICAL_LAB_ORIGIN,issuer,check_lab_database)


@csrf_exempt
def api(request,action):
    # No cookie-based authorization: high entropy operator capability + exact
    # same-origin request checks + assertion and proof-bound signed actions.
    def execute():
        body=post_body(request)
        data=json.loads(body.decode("utf-8"),object_pairs_hook=no_duplicates)
        return lab().call(action,data,body,request)
    return response_or_refusal(execute)


def asset(request,name="index.html"):
    try:
        boundary(request)
        require(request.method=="GET" and (name in MODULES or name in ("index.html","physical.css")))
        mime="text/html; charset=utf-8" if name.endswith(".html") else (
            "text/css; charset=utf-8" if name.endswith(".css") else "text/javascript; charset=utf-8")
        return protected(HttpResponse((STATIC/name).read_bytes(),content_type=mime))
    except Exception:
        return protected(HttpResponse("Refused",status=403))


urlpatterns=[
    path("",asset),
    path("physical/<str:action>",api),
    path("assets/<str:name>",asset),
]
