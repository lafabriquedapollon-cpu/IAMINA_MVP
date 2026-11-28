"""P2a CI-only HTTPS boundary. No URLconf, enrollment or production account adapter.

A trusted fixture supplies an already enrolled credential and inventory.
A one-use WebAuthn challenge gates the session proof key; PRF stays client-side.
This is not yet a remotely hosted TLS endpoint or a durable server counter.
"""
import base64
import hashlib
import json
import secrets
import time
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import connection

from core.d1_prf_authority_candidate import (
    ProvisionAuthority, Refused, VerifiedContext, canonical_b64, require,
)
from core.d1_prf_transport_candidate import CandidateTransport, no_duplicates

ORIGIN = "https://iamina-qualification.test"
RP_ID = "iamina-qualification.test"
DB = "test_iamina_phase1_ci"


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(value):
    require(type(value) is str and len(value) <= 8192 and canonical_b64(value))
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class HttpsQualificationAuthority(ProvisionAuthority):
    def __init__(self, *, signing_key, origin):
        require(origin == ORIGIN and isinstance(signing_key, ec.EllipticCurvePrivateKey)
                and isinstance(signing_key.curve, ec.SECP256R1))
        self._key, self._origin = signing_key, origin

    def _locked(self, owner, work):
        require(connection.vendor == "postgresql"
                and connection.settings_dict["NAME"] == DB
                and connection.settings_dict["HOST"] == "127.0.0.1")
        return super()._locked(owner, work)


class HttpsQualificationTransport(CandidateTransport):
    def __init__(self, authority):
        require(type(authority) is HttpsQualificationAuthority)
        super().__init__(authority, ORIGIN)
        self.challenges = {}
        self.challenge_lock = Lock()

    def add_verified_fixture(self, context, public_key):
        # Never allow the loopback synthetic session shortcut in this adapter.
        raise Refused("D1_PRF_AUTHORIZATION_REFUSED")

    def begin(self, context, proof_public_key):
        """Internal trusted enrollment boundary, not an HTTP handler."""
        self.authority._context(context)
        require(type(context) is VerifiedContext and
                isinstance(proof_public_key, ec.EllipticCurvePublicKey) and
                isinstance(proof_public_key.curve, ec.SECP256R1))
        credential_id, spki, rp_id, origin = json.loads(context.binding)
        require(rp_id == RP_ID and origin == ORIGIN)
        key = serialization.load_der_public_key(decode(spki))
        require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1))
        require(key.public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo) == decode(spki))
        challenge = b64(secrets.token_bytes(32))
        with self.challenge_lock:
            now = time.monotonic()
            self.challenges = {k: v for k, v in self.challenges.items() if v[0] > now}
            require(len(self.challenges) < 16)
            self.challenges[challenge] = (now + 60, context, proof_public_key, credential_id, key)
        return challenge

    def finish(self, challenge, *, credential_id, client_data, authenticator_data, signature):
        """Consume a server challenge even when the assertion is invalid."""
        try:
            require(type(challenge) is str and len(challenge) == 43)
            with self.challenge_lock:
                pending = self.challenges.pop(challenge, None)
            require(pending is not None)
            expires, context, proof_key, expected_id, key = pending
            require(time.monotonic() < expires and credential_id == expected_id)
            require(type(client_data) is bytes and 0 < len(client_data) <= 8192 and
                    type(authenticator_data) is bytes and 37 <= len(authenticator_data) <= 4096 and
                    type(signature) is bytes and 0 < len(signature) <= 80)
            client = json.loads(client_data.decode("utf-8"), object_pairs_hook=no_duplicates)
            require(type(client) is dict and client.get("type") == "webauthn.get"
                    and client.get("challenge") == challenge and client.get("origin") == ORIGIN
                    and client.get("crossOrigin", False) is False and "topOrigin" not in client)
            require(secrets.compare_digest(authenticator_data[:32], hashlib.sha256(RP_ID.encode()).digest()))
            flags = authenticator_data[32]
            require(flags & 5 == 5 and not flags & 0x40
                    and (not flags & 0x10 or flags & 0x08)
                    and (len(authenticator_data) > 37 if flags & 0x80 else len(authenticator_data) == 37))
            key.verify(signature, authenticator_data + hashlib.sha256(client_data).digest(),
                       ec.ECDSA(hashes.SHA256()))
            require(time.monotonic() < expires)
            # The browser must still prove the separate, challenge-bound session key.
            # This internal superclass call is only reached after signature verification.
            return super().add_verified_fixture(context, proof_key)
        except Exception:
            raise Refused("D1_PRF_AUTHORIZATION_REFUSED") from None

    def _handle(self, request):
        # Native TLS WSGI only for this candidate; never infer TLS from proxy headers.
        require(request.META.get("wsgi.url_scheme") == "https" and request.is_secure()
                and not any(h in request.META for h in (
                    "HTTP_FORWARDED", "HTTP_X_FORWARDED_PROTO", "HTTP_X_FORWARDED_HOST",
                    "HTTP_X_FORWARDED_PORT", "HTTP_X_FORWARDED_SSL",
                )))
        return super()._handle(request)
