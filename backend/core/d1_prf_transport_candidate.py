"""Synthetic loopback adapter only. Never register in product URLconf.

The trusted harness supplies independently verified contexts and a session
proof key. This is proof of possession of a synthetic session key, NOT
WebAuthn, real account authentication, or production session persistence.
"""
import json
import secrets
import time
from dataclasses import dataclass, field
from threading import Lock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from django.http import JsonResponse

from core.d1_prf_authority_candidate import Refused, VerifiedContext, hex_id, require

PATH = "/d1-provision-candidate"
LIMIT = 32768


def exact(obj, fields):
    return type(obj) is dict and set(obj) == set(fields)


def no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        require(k not in obj)
        obj[k] = v
    return obj


def proof_bytes(session_id, body):
    return b"IAMINA-D1-SESSION-PROOF-V1\n" + session_id.encode("ascii") + b"\n" + body


@dataclass
class _Session:
    context: VerifiedContext
    key: ec.EllipticCurvePublicKey
    expires: float
    seen: set = field(default_factory=set)
    lock: Lock = field(default_factory=Lock)
    revoked: bool = False


class CandidateTransport:
    def __init__(self, authority, origin):
        require(authority._origin == origin)
        self.authority, self.origin = authority, origin
        self.sessions = {}
        self.lock = Lock()

    def add_verified_fixture(self, context, public_key):
        self.authority._context(context)
        require(isinstance(public_key, ec.EllipticCurvePublicKey)
                and isinstance(public_key.curve, ec.SECP256R1))
        session_id = secrets.token_hex(32)
        with self.lock:
            require(len(self.sessions) < 16)
            self.sessions[session_id] = _Session(context, public_key, time.monotonic()+120)
        return session_id

    def revoke(self, session_id):
        with self.lock:
            session = self.sessions.get(session_id)
        if session:
            with session.lock:
                session.revoked = True

    def __call__(self, request):
        try:
            result = self._handle(request)
            response = JsonResponse(result)
        except Exception:
            # Fail closed, including malformed JSON, crypto and unavailable DB.
            # A refusal is not proof that a prior commit did not occur.
            response = JsonResponse({"error": "D1_PRF_AUTHORIZATION_REFUSED"}, status=403)
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response

    def _handle(self, request):
        require(request.method == "POST" and request.path == PATH
                and request.get_host() == self.origin.split("://",1)[1]
                and request.headers.get("Origin") == self.origin
                and request.headers.get("Sec-Fetch-Site") == "same-origin"
                and request.content_type == "application/json")
        length = request.META.get("CONTENT_LENGTH", "")
        require(length.isascii() and length.isdecimal() and 0 < int(length) <= LIMIT)
        body = request.body
        require(len(body) == int(length))
        session_id = request.headers.get("X-D1-Session")
        signature = request.headers.get("X-D1-Proof")
        require(hex_id(session_id) and type(signature) is str and len(signature)==128
                and all(c in "0123456789abcdef" for c in signature))
        with self.lock:
            session = self.sessions.get(session_id)
        require(session is not None)
        data = json.loads(body.decode("utf-8"), object_pairs_hook=no_duplicates)
        require(exact(data, ("action","requestId","payload")) and hex_id(data["requestId"]))
        raw = bytes.fromhex(signature)
        session.key.verify(encode_dss_signature(int.from_bytes(raw[:32],"big"),
                            int.from_bytes(raw[32:],"big")), proof_bytes(session_id, body),
                           ec.ECDSA(hashes.SHA256()))
        with session.lock:
            require(not session.revoked and time.monotonic() < session.expires
                    and data["requestId"] not in session.seen and len(session.seen)<128)
            session.seen.add(data["requestId"])
            ctx, action, p = session.context, data["action"], data["payload"]
            if action == "reserve":
                require(exact(p, ()))
                e = self.authority.reserve(ctx)
                return {"ticket": e["ticket"], "signature": e["signature"].hex()}
            if action == "redeem":
                require(exact(p, ("ticket","signature")) and type(p["signature"]) is str
                        and len(p["signature"]) == 128
                        and all(c in "0123456789abcdef" for c in p["signature"]))
                require(self.authority.redeem(ctx, p["ticket"], bytes.fromhex(p["signature"])))
                return {"redeemed": True}
            if action == "status":
                require(exact(p, ("operationId",)))
                return {"state": self.authority.status(ctx, p["operationId"])}
            raise Refused("D1_PRF_AUTHORIZATION_REFUSED")
