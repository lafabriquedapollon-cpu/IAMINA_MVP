import json

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from core.consent_notice import expected_notice_claim
from core.models import AIConsentReceipt, BasePatientProfile, D3FeatureIntent
from core.native_auth import issue_native_token, revoke_native_tokens

pytestmark = pytest.mark.django_db
PATH = "/api/v1/account/ai-feature-intents"


def identity(name):
    user = User.objects.create_user(username=name)
    token = issue_native_token(user)
    return user, {"HTTP_AUTHORIZATION": f"Bearer {token}"}


def receipt(user):
    claim = expected_notice_claim("fr")
    now = timezone.now()
    AIConsentReceipt.objects.filter(patient=user, revoked_at__isnull=True).update(revoked_at=now)
    BasePatientProfile.objects.filter(patient=user).update(
        ai_consent_given_at=now, ai_consent_notice_version=claim.version,
        ai_consent_notice_hash=claim.notice_hash, ai_consent_notice_locale=claim.locale,
    )
    return AIConsentReceipt.objects.create(patient=user, notice_version=claim.version,
        notice_hash=claim.notice_hash, notice_locale=claim.locale, granted_at=now)


def read(client, headers, locale="fr"):
    response = client.get(PATH, {"locale": locale}, **headers)
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["features"]) == 3
    assert all(not state["activation_available"] and not state["external_ai_authorized"] for state in payload["features"])
    return payload


def put(client, headers, feature, payload):
    return client.put(f"{PATH}/{feature}", data=json.dumps(payload), content_type="application/json", **headers)


def test_default_disabled_and_auth_required(settings):
    user, headers = identity("d3-http-a")
    client = Client()
    assert client.get(PATH, **headers).status_code == 404
    settings.D3_FEATURE_INTENTS_API_ENABLED = True
    assert client.get(PATH).status_code in (401, 403)
    assert client.get(PATH, HTTP_AUTHORIZATION="Bearer invalid").status_code in (401, 403)
    client.force_login(user)
    assert client.get(PATH).status_code in (401, 403)
    client.logout()
    revoke_native_tokens(user)
    assert client.get(PATH, **headers).status_code in (401, 403)
    assert D3FeatureIntent.objects.count() == 0


def test_exact_notice_independent_owner_scope_and_replay(settings):
    settings.D3_FEATURE_INTENTS_API_ENABLED = True
    a, ha = identity("d3-http-a")
    b, hb = identity("d3-http-b")
    ra = receipt(a)
    receipt(b)
    client = Client()
    payload = read(client, ha, "ar")
    assert payload["global_receipt_id"] == ra.pk
    assert all(not state["intent_enabled"] for state in payload["features"])
    grant = {"enabled": True, "expected_revision": 0, "expected_global_receipt_id": ra.pk, "notice": payload["notices"]["photo"]}
    assert put(client, ha, "photo", {**grant, "patient_id": b.pk}).status_code == 422
    assert put(client, ha, "photo", {**grant, "enabled": "true"}).status_code == 422
    assert put(client, ha, "photo", {**grant, "notice": payload["notices"]["habits"]}).status_code == 422
    response = put(client, ha, "photo", grant)
    assert response.status_code == 200
    assert response.json()["intent_enabled"] is True
    assert response.json()["external_ai_authorized"] is False
    assert all(not state["intent_enabled"] for state in read(client, hb)["features"])
    assert put(client, ha, "photo", {"enabled": False, "expected_revision": 1}).status_code == 200
    assert put(client, ha, "photo", grant).status_code == 409
    assert all(not state["intent_enabled"] for state in read(client, ha)["features"])


def test_stale_global_epoch_cannot_enable_new_feature(settings):
    settings.D3_FEATURE_INTENTS_API_ENABLED = True
    a, ha = identity("d3-http-a")
    old = receipt(a)
    client = Client()
    payload = read(client, ha)
    current = receipt(a)
    assert current.pk != old.pk
    grant = {"enabled": True, "expected_revision": 0, "expected_global_receipt_id": old.pk, "notice": payload["notices"]["companion"]}
    assert put(client, ha, "companion", grant).status_code == 409
    assert D3FeatureIntent.objects.count() == 0
    assert put(client, ha, "companion", {**grant, "expected_global_receipt_id": current.pk}).status_code == 200
    receipt(a)
    assert all(not state["intent_enabled"] for state in read(client, ha)["features"])


def test_missing_receipt_and_invalid_locale_are_denied(settings):
    settings.D3_FEATURE_INTENTS_API_ENABLED = True
    _, ha = identity("d3-http-a")
    client = Client()
    payload = read(client, ha)
    assert payload["global_receipt_id"] is None
    assert client.get(PATH, {"locale": "unknown"}, **ha).status_code == 422
    assert put(client, ha, "photo", {"enabled": True, "expected_revision": 0, "notice": payload["notices"]["photo"]}).status_code == 422
    assert D3FeatureIntent.objects.count() == 0
