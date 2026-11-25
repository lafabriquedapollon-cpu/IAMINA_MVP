import pytest
from django.contrib.auth.models import AnonymousUser, User
from django.utils import timezone

from core.consent_notice import expected_notice_claim
from core.d3_feature_intents import notice_for, read_feature_intents, record_feature_intent
from core.models import AIConsentReceipt, BasePatientProfile, D3FeatureIntent

pytestmark = pytest.mark.django_db


def owner(name):
    return User.objects.create_user(username=name)


def global_receipt(user):
    claim = expected_notice_claim("fr")
    now = timezone.now()
    BasePatientProfile.objects.update_or_create(patient=user, defaults={
        "ai_consent_given_at": now,
        "ai_consent_notice_version": claim.version,
        "ai_consent_notice_hash": claim.notice_hash,
        "ai_consent_notice_locale": claim.locale,
    })
    return AIConsentReceipt.objects.create(patient=user, notice_version=claim.version,
        notice_hash=claim.notice_hash, notice_locale=claim.locale, granted_at=now)


def state(user):
    result = read_feature_intents(user)
    assert len(result) == 3
    assert all(not item["activation_available"] and not item["external_ai_authorized"] for item in result)
    return {item["feature"]: item for item in result}


def test_defaults_off_no_rows_and_no_legacy_backfill():
    user = owner("d3-a")
    global_receipt(user)
    assert all(not x["intent_enabled"] and x["revision"] == 0 for x in state(user).values())
    assert D3FeatureIntent.objects.count() == 0


def test_independent_scopes_owner_isolation_and_immediate_off():
    a, b = owner("d3-a"), owner("d3-b")
    global_receipt(a)
    global_receipt(b)
    for feature in ("photo", "habits"):
        record_feature_intent(a, feature=feature, enabled=True, expected_revision=0, notice=notice_for(feature, "ar"))
    assert state(a)["photo"]["intent_enabled"]
    assert state(a)["habits"]["intent_enabled"]
    assert not state(a)["companion"]["intent_enabled"]
    assert all(not x["intent_enabled"] for x in state(b).values())
    record_feature_intent(a, feature="photo", enabled=False, expected_revision=1)
    assert not state(a)["photo"]["intent_enabled"]
    assert state(a)["habits"]["intent_enabled"]


def test_stale_revision_wrong_notice_and_missing_receipt_denied():
    a = owner("d3-a")
    with pytest.raises(ValueError):
        record_feature_intent(a, feature="photo", enabled=True, expected_revision=0, notice=notice_for("photo", "fr"))
    global_receipt(a)
    with pytest.raises(ValueError):
        record_feature_intent(a, feature="photo", enabled=True, expected_revision=0, notice=notice_for("habits", "fr"))
    record_feature_intent(a, feature="photo", enabled=True, expected_revision=0, notice=notice_for("photo", "fr"))
    record_feature_intent(a, feature="photo", enabled=False, expected_revision=1)
    with pytest.raises(ValueError, match="Stale"):
        record_feature_intent(a, feature="photo", enabled=True, expected_revision=1, notice=notice_for("photo", "fr"))
    assert not state(a)["photo"]["intent_enabled"]


def test_global_withdrawal_and_new_receipt_never_restore_old_intent():
    a = owner("d3-a")
    receipt = global_receipt(a)
    record_feature_intent(a, feature="companion", enabled=True, expected_revision=0, notice=notice_for("companion", "en"))
    receipt.revoked_at = timezone.now()
    receipt.save(update_fields=["revoked_at"])
    assert not state(a)["companion"]["intent_enabled"]
    global_receipt(a)
    assert not state(a)["companion"]["intent_enabled"]
    assert state(a)["companion"]["revision"] == 1


def test_anonymous_and_unknown_feature_rejected():
    with pytest.raises(ValueError):
        read_feature_intents(AnonymousUser())
    a = owner("d3-a")
    with pytest.raises(ValueError):
        record_feature_intent(a, feature="all", enabled=False, expected_revision=0)
    assert D3FeatureIntent.objects.count() == 0
