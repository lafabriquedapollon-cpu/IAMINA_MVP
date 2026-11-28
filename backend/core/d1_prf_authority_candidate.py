"""Isolated B2c.3 server authority, synthetic owners only.

No public route, migration, production inventory or account verification.
The trusted server composition MUST supply a freshly verified account and
credential binding; this module does not turn a bearer into that proof.
Only the test harness creates/populates the dedicated table. Missing inventory
is never evidence of a fresh account. A reserved or redeemed slot is terminal
for new issuance, including after expiry or a lost response.
"""
import base64
import json
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)
from django.db import DatabaseError, connection, transaction

TABLE = "d1_prf_authority_candidate"
OWNERS = {900001, 900002}
MAX_SAFE = 2**53 - 1
PURPOSE = "IAMINA-D1-FRESH-PROVISION-V1"
FIELDS = ("owner", "binding", "epoch", "generation", "nonce")
TICKET_FIELDS = ("version", "purpose", *FIELDS, "operationId", "issuedAt", "expiresAt")
HEX = re.compile(r"[0-9a-f]{64}")
B64 = re.compile(r"[A-Za-z0-9_-]+")


class Refused(Exception):
    """Generic refusal; no underlying database or key details returned."""


def require(ok):
    if not ok:
        raise Refused("D1_PRF_AUTHORIZATION_REFUSED")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def canonical_b64(value):
    if not B64.fullmatch(value):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return bool(raw) and base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") == value
    except (ValueError, TypeError):
        return False


def stored_ticket(ticket):
    # Wire JSON object key order is not authority; signed field order is fixed.
    return canonical({k: ticket[k] for k in TICKET_FIELDS})


def ticket_bytes(ticket):
    require(type(ticket) is dict and set(ticket) == set(TICKET_FIELDS))
    return canonical([ticket[k] for k in TICKET_FIELDS]).encode("utf-8")


def uint(value):
    return type(value) is int and 0 <= value <= MAX_SAFE


def hex_id(value):
    return type(value) is str and HEX.fullmatch(value) is not None


@dataclass(frozen=True)
class VerifiedContext:
    """Internal adapter input, NOT a proof minted by this candidate."""
    owner: int
    binding: str
    epoch: int
    generation: int
    nonce: str

    def fields(self, origin):
        require(type(self.owner) is int and self.owner in OWNERS and
                uint(self.epoch) and uint(self.generation) and self.generation > 0 and
                hex_id(self.nonce) and type(self.binding) is str and len(self.binding) <= 16384)
        try:
            b = json.loads(self.binding)
            require(type(b) is list and len(b) == 4 and all(type(x) is str and x for x in b))
            require(all(canonical_b64(x) for x in b[:2]) and b[2] == urlsplit(origin).hostname
                    and b[3] == origin and canonical(b) == self.binding)
        except (ValueError, TypeError, UnicodeError):
            raise Refused("D1_PRF_AUTHORIZATION_REFUSED") from None
        return dict(zip(FIELDS, (self.owner, self.binding, self.epoch, self.generation, self.nonce)))


class ProvisionAuthority:
    def __init__(self, *, signing_key, origin):
        require(isinstance(signing_key, ec.EllipticCurvePrivateKey) and
                isinstance(signing_key.curve, ec.SECP256R1))
        # Candidate is deliberately confined to synthetic loopback.
        u = urlsplit(origin)
        require(u.scheme == "http" and u.hostname == "127.0.0.1" and u.port is not None
                and u.path == "" and not u.query and not u.fragment and not u.username
                and origin == f"http://127.0.0.1:{u.port}")
        self._key = signing_key
        self._origin = origin

    def _context(self, ctx):
        require(type(ctx) is VerifiedContext)
        return ctx.fields(self._origin)

    def _locked(self, owner, work):
        # Commit ACK must come from the outermost transaction, not a savepoint.
        require(connection.vendor == "postgresql" and connection.get_autocommit()
                and not connection.in_atomic_block)
        try:
            with transaction.atomic(durable=True):
                with connection.cursor() as cur:
                    cur.execute("SET LOCAL synchronous_commit = on")
                    cur.execute("SET LOCAL lock_timeout = '2s'")
                    cur.execute("SET LOCAL statement_timeout = '4s'")
                    cur.execute(f"SELECT state, binding, ticket, signature FROM {TABLE} WHERE owner = %s FOR UPDATE", [owner])
                    row = cur.fetchone()
                    require(row is not None)
                    cur.execute("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                    now = cur.fetchone()[0]
                    result = work(cur, row, now)
            return result
        except DatabaseError:
            raise Refused("D1_PRF_AUTHORIZATION_REFUSED") from None

    def reserve(self, ctx):
        fields = self._context(ctx)

        def work(cur, row, now):
            state, binding, stored, signature = row
            require(state == "fresh" and binding == ctx.binding and stored is None and signature is None)
            ticket = {"version": 1, "purpose": PURPOSE, **fields,
                      "operationId": secrets.token_hex(32), "issuedAt": now, "expiresAt": now + 60000}
            der = self._key.sign(ticket_bytes(ticket), ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            cur.execute(f"UPDATE {TABLE} SET state = 'reserved', ticket = %s, signature = %s WHERE owner = %s",
                        [stored_ticket(ticket), sig, ctx.owner])
            require(cur.rowcount == 1)
            return {"ticket": ticket, "signature": sig}

        return self._locked(ctx.owner, work)

    def redeem(self, ctx, ticket, signature):
        fields = self._context(ctx)
        try:
            raw = ticket_bytes(ticket)
            require(type(ticket["version"]) is int and ticket["version"] == 1 and ticket["purpose"] == PURPOSE
                    and all(type(ticket[k]) is type(v) and ticket[k] == v for k, v in fields.items())
                    and hex_id(ticket["operationId"]) and uint(ticket["issuedAt"]) and uint(ticket["expiresAt"])
                    and 0 < ticket["expiresAt"] - ticket["issuedAt"] <= 60000
                    and type(signature) is bytes and len(signature) == 64)
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            self._key.public_key().verify(encode_dss_signature(r, s), raw, ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise Refused("D1_PRF_AUTHORIZATION_REFUSED") from None

        def work(cur, row, now):
            state, binding, stored, sig = row
            require(state == "reserved" and binding == ctx.binding and stored == stored_ticket(ticket)
                    and sig is not None and secrets.compare_digest(bytes(sig), signature)
                    and ticket["issuedAt"] <= now < ticket["expiresAt"])
            cur.execute(f"UPDATE {TABLE} SET state = 'redeemed' WHERE owner = %s", [ctx.owner])
            require(cur.rowcount == 1)
            return True

        return self._locked(ctx.owner, work)

    def status(self, ctx, operation_id):
        fields = self._context(ctx)
        require(hex_id(operation_id))

        def work(_cur, row, _now):
            state, binding, stored, _sig = row
            require(state in ("reserved", "redeemed") and binding == ctx.binding and type(stored) is str)
            t = json.loads(stored)
            require(t["operationId"] == operation_id and all(t[k] == v for k, v in fields.items()))
            # Redeemed is not proof that the browser committed a vault.
            return state

        return self._locked(ctx.owner, work)
