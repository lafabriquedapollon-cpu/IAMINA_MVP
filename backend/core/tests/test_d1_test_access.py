"""Synthetic HTTP regression: ordinary authenticated test access, not vault attestation."""
import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from core.models import BasePatientProfile, D3FeatureIntent
from core.native_auth import issue_native_token, verify_native_token, NativeTokenError

pytestmark = pytest.mark.django_db


def test_test_access_requires_real_auth_not_client_version(settings):
    settings.D3_FEATURE_INTENTS_API_ENABLED = True
    user = User.objects.create_user(username="d1-test-access")
    token = issue_native_token(user)
    bearer = {"HTTP_AUTHORIZATION": "Bearer " + token}
    spoofed = {"HTTP_X_CLIENT_VERSION": "999.0.0", "HTTP_X_IAMINA_VAULT_VERSION": "2"}
    client = Client()
    path = "/api/v1/account/ai-feature-intents"
    assert client.get(path).status_code in (401, 403)
    assert client.get(path, **spoofed).status_code in (401, 403)
    assert client.get(path, HTTP_AUTHORIZATION="Bearer invalid", **spoofed).status_code in (401, 403)
    client.force_login(user)
    assert client.get(path, **spoofed).status_code in (401, 403)
    client.logout()
    for headers in (bearer, {**bearer, **spoofed}):
        response = client.get(path, **headers)
        assert response.status_code == 200
        assert len(response.json()["features"]) == 3
        assert all(not x["activation_available"] and not x["external_ai_authorized"]
                   for x in response.json()["features"])
    assert D3FeatureIntent.objects.count() == 0
    assert client.post("/api/v1/auth/logout", **bearer).status_code == 200
    assert client.get(path, **bearer, **spoofed).status_code in (401, 403)


def test_health_logout_and_consent_withdrawal_remain_available():
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
