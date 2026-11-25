"""Actual Django request boundary during explicit cutover, synthetic PG only."""
import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from core.models import BasePatientProfile, D3FeatureIntent
from core.native_auth import issue_native_token, verify_native_token, NativeTokenError

pytestmark = pytest.mark.django_db


def test_valid_bearer_cookie_and_spoofed_version_cannot_bypass(settings, django_assert_num_queries):
    settings.D3_FEATURE_INTENTS_API_ENABLED = True
    settings.D1_CUTOVER_FREEZE = False
    user = User.objects.create_user(username="cutover-a")
    token = issue_native_token(user)
    bearer = {"HTTP_AUTHORIZATION": "Bearer " + token}
    client = Client()
    path = "/api/v1/account/ai-feature-intents"
    assert client.get(path, **bearer).status_code == 200
    settings.D1_CUTOVER_FREEZE = True
    client.force_login(user)
    for headers in ({}, bearer, {**bearer, "HTTP_X_CLIENT_VERSION": "999.0.0",
                                 "HTTP_X_IAMINA_VAULT_VERSION": "2"}):
        for method, target in [
            ("GET", path), ("PUT", path + "/photo"),
            ("GET", "/api/v1/profile"), ("POST", "/api/v1/logs"),
            ("GET", "/api/v1/account/consent"),
            ("POST", "/api/v1/account/consent"),
            ("GET", "/api/v1/auth/me"), ("POST", "/api/v1/auth/login"),
            ("POST", "/api/v1/auth/register"), ("GET", "/api/v1/app-compatibility"),
            ("POST", "/api/v1/auth/logout/"), ("DELETE", "/api/v1/account"),
            ("GET", "/admin/"), ("POST", "/api/v1/health"),
        ]:
            with django_assert_num_queries(0):
                response = client.generic(method, target, **headers)
            assert response.status_code == 423, (method, target, response.status_code)
            assert response.json()["error"]["code"] == "encrypted_vault_cutover"
            assert response.json()["error"]["retryable"] is False
            assert response["Cache-Control"] == "no-store"
    assert D3FeatureIntent.objects.count() == 0
    assert User.objects.count() == 1
    settings.D1_CUTOVER_FREEZE = False
    assert client.get(path, **bearer).status_code == 200


def test_health_logout_and_consent_withdrawal_remain_available(settings):
    settings.D1_CUTOVER_FREEZE = True
    user = User.objects.create_user(username="cutover-privacy")
    token = issue_native_token(user)
    headers = {"HTTP_AUTHORIZATION": "Bearer " + token}
    BasePatientProfile.objects.filter(patient=user).update(ai_consent_given_at=timezone.now())
    client = Client()
    assert client.get("/api/v1/health").status_code == 200
    assert client.delete("/api/v1/account/consent").status_code in (401, 403)
    response = client.delete("/api/v1/account/consent", **headers)
    assert response.status_code == 200, response.content
    assert BasePatientProfile.objects.get(patient=user).ai_consent_given_at is None
    assert client.post("/api/v1/auth/logout", **headers).status_code == 200
    with pytest.raises(NativeTokenError):
        verify_native_token(token)
