"""Physical lab session persistence; not registered in any URLconf.

Trusted operator composition must authenticate enrollment and supply a preseeded
synthetic credential binding. No public enrollment, no PRF output accepted.
Database inventory and tables are provisioned separately, never by this module.
The CI adapter stays loopback-only; hosted wiring requires review and approval.
"""
import hashlib
import json
import secrets
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from django.db import connection, transaction

from core.d1_prf_authority_candidate import (
    Refused, VerifiedContext, canonical, hex_id, require,
)
from core.d1_prf_https_qualification_candidate import b64, decode
from core.d1_prf_transport_candidate import no_duplicates, proof_bytes, exact

SESSION_TABLE = "d1_physical_lab_session_candidate"
LAB_HOST = "ep-frosty-tooth-b921hjv8-pooler.c-7.eu-central-1.aws.neon.tech"
LAB_DB = "iamina925_empty"
LAB_ROLE = "d1_safari_runtime"


def check_lab_database():
    """Guard before any session-table SQL; no fallback to product inventory."""
    cfg = connection.settings_dict
    require(connection.vendor == "postgresql" and cfg["HOST"] == LAB_HOST
            and cfg["NAME"] == LAB_DB and cfg["USER"] == LAB_ROLE
            and cfg.get("OPTIONS", {}).get("sslmode") == "verify-full")
    with connection.cursor() as cur:
        cur.execute("SELECT current_database(), current_user, current_setting('server_version_num')::integer")
        name, role, version = cur.fetchone()
    require(name == LAB_DB and role == LAB_ROLE and 160000 <= version < 170000)


class DurablePhysicalSessions:
    """Internal composition: preverified operator context, actual signed assertion.

    One row per synthetic owner, one outstanding challenge, one current session.
    Challenge and replay state survive process replacement. No runtime INSERT.
    """
    def __init__(self, origin, check_database):
        u = urlsplit(origin)
        require(u.scheme == "https" and u.hostname and not u.username
                and origin == "https://" + u.hostname)
        self.origin, self.rp_id, self.check_database = origin, u.hostname, check_database

    def _locked(self, owner, work):
        require(type(owner) is int and owner in (900001,900002)
                and connection.get_autocommit() and not connection.in_atomic_block)
        self.check_database()
        with transaction.atomic(durable=True):
            with connection.cursor() as cur:
                cur.execute("SET LOCAL synchronous_commit = on")
                cur.execute("SET LOCAL lock_timeout = '2s'")
                cur.execute("SET LOCAL statement_timeout = '4s'")
                cur.execute(f"SELECT context, pending, session FROM {SESSION_TABLE} WHERE owner=%s FOR UPDATE",[owner])
                row = cur.fetchone()
                require(row is not None)
                cur.execute("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                now = cur.fetchone()[0]
                return work(cur,row,now)

    def _context(self, value):
        ctx = VerifiedContext(**json.loads(value))
        ctx.fields(self.origin)
        return ctx

    def _public_key(self, spki):
        raw = decode(spki)
        key = serialization.load_der_public_key(raw)
        require(isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256R1)
                and key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)==raw)
        return key

    def begin(self, owner, proof_spki):
        self._public_key(proof_spki)
        challenge = b64(secrets.token_bytes(32))
        def work(cur,row,now):
            ctx = self._context(row[0])
            require(ctx.owner == owner)
            # An existing authenticated session is not silently replaced by begin.
            require(row[1] is None or json.loads(row[1])["expires"] <= now)
            p = canonical({"challenge":challenge,"proof":proof_spki,"expires":now+60000})
            cur.execute(f"UPDATE {SESSION_TABLE} SET pending=%s WHERE owner=%s",[p,owner])
            return {"challenge":challenge,"context":ctx.fields(self.origin)}
        return self._locked(owner,work)

    def finish(self, owner, challenge, credential_id, client_data, auth_data, signature):
        # A matching challenge is consumed even on failed verification.
        def work(cur,row,now):
            ctx = self._context(row[0])
            p = json.loads(row[1]) if row[1] else None
            require(p is not None and p["challenge"] == challenge)
            cur.execute(f"UPDATE {SESSION_TABLE} SET pending=NULL WHERE owner=%s",[owner])
            try:
                require(now < p["expires"] and ctx.owner == owner)
                cid,spki,rp,origin = json.loads(ctx.binding)
                require(cid == credential_id and rp == self.rp_id and origin == self.origin)
                require(type(client_data) is bytes and 0 < len(client_data)<=8192
                        and type(auth_data) is bytes and 37<=len(auth_data)<=4096
                        and type(signature) is bytes and 0<len(signature)<=80)
                client=json.loads(client_data.decode("utf-8"),object_pairs_hook=no_duplicates)
                require(type(client) is dict and client.get("type")=="webauthn.get"
                        and client.get("challenge")==challenge and client.get("origin")==origin
                        and client.get("crossOrigin",False) is False and "topOrigin" not in client)
                require(secrets.compare_digest(auth_data[:32],hashlib.sha256(rp.encode()).digest()))
                flags=auth_data[32]
                require(flags & 5 == 5 and not flags & 0x40 and (not flags & 0x10 or flags & 8)
                        and (len(auth_data)>37 if flags & 0x80 else len(auth_data)==37))
                self._public_key(spki).verify(signature,auth_data+hashlib.sha256(client_data).digest(),
                                              ec.ECDSA(hashes.SHA256()))
                count=int.from_bytes(auth_data[33:37],"big")
                # Durable monotonic count is distinct from local PRF CAS; zero-to-zero permitted.
                cur.execute(f"SELECT sign_count FROM {SESSION_TABLE} WHERE owner=%s",[owner])
                previous=cur.fetchone()[0]
                require((previous==0 and count==0) or count>previous)
                sid=secrets.token_hex(32)
                session=canonical({"id":sid,"proof":p["proof"],"expires":now+120000,"seen":[]})
            except Exception:
                return None
            cur.execute(f"UPDATE {SESSION_TABLE} SET session=%s,sign_count=%s WHERE owner=%s",
                        [session,count,owner])
            return {"sessionId":sid,"context":ctx.fields(self.origin)}
        result=self._locked(owner,work)
        require(result is not None)
        return result

    def claim(self,owner,sid,body,signature,*,dispatch=None):
        """Consume a signed request ID durably before dispatching to the authority.

        A crash after claim may lose the response; never reset inventory or reissue.
        An already claimed request can finish after a later session replacement.
        """
        require(hex_id(sid) and type(body) is bytes and 0<len(body)<=32768
                and type(signature) is bytes and len(signature)==64)
        data=json.loads(body.decode("utf-8"),object_pairs_hook=no_duplicates)
        require(exact(data,("action","requestId","payload")) and hex_id(data["requestId"])
                and data["action"] in ("reserve","redeem","status"))
        def work(cur,row,now):
            ctx=self._context(row[0])
            s=json.loads(row[2]) if row[2] else None
            require(ctx.owner==owner and s is not None and secrets.compare_digest(s["id"],sid)
                    and now<s["expires"] and data["requestId"] not in s["seen"] and len(s["seen"])<128)
            try:
                r=int.from_bytes(signature[:32],"big")
                t=int.from_bytes(signature[32:],"big")
                self._public_key(s["proof"]).verify(encode_dss_signature(r,t),proof_bytes(sid,body),
                                                    ec.ECDSA(hashes.SHA256()))
            except Exception:
                raise Refused("D1_PRF_AUTHORIZATION_REFUSED") from None
            s["seen"].append(data["requestId"])
            cur.execute(f"UPDATE {SESSION_TABLE} SET session=%s WHERE owner=%s",[canonical(s),owner])
            if dispatch is None:
                return ctx,data
            try:
                # Keep the replay consumption even when the authority refuses.
                # Database failures roll back the whole transaction.
                with transaction.atomic():
                    return dispatch(ctx,data)
            except Refused:
                return None
        result=self._locked(owner,work)
        require(result is not None)
        return result
