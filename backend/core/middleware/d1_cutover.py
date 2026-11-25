"""Temporary API cutover hold, not an identity or client-version attestation.

A header, user agent or origin does not prove an encrypted client. Until the
new admission contract is certified, refuse all clinical routes (including
GET handlers that may have side effects). Keep only exact safety exceptions.
Requires operational authorization and draining in-flight requests before a
real cutover. It cannot fence offline writes by already-loaded browsers.
"""
from django.conf import settings
from django.http import JsonResponse

_ALLOWED = frozenset({
    ("GET", "/api/v1/health"),
    ("HEAD", "/api/v1/health"),
    ("POST", "/api/v1/auth/logout"),
    ("DELETE", "/api/v1/account/consent"),
})


class D1CutoverFreezeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(settings, "D1_CUTOVER_FREEZE", False) is False:
            return self.get_response(request)
        if (request.method, request.path_info) in _ALLOWED:
            return self.get_response(request)
        response = JsonResponse(
            {"error": {"code": "encrypted_vault_cutover",
                       "message": "Patient access is temporarily unavailable.",
                       "retryable": False}},
            status=423,
        )
        response["Cache-Control"] = "no-store"
        return response
