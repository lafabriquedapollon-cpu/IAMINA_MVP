"""D3 candidate preference service; HTTP access is separately default-denied.

A true intent is not consent to send data or activate a provider. No provider
authorization is returned. Notice strings are candidate product copy; the exact
displayed notice and release gates must be qualified before enabling any UI.
"""
from hashlib import sha256

from django.contrib.auth.models import User
from django.db import transaction

from core.consent_notice import profile_has_current_consent
from core.models import AIConsentReceipt, BasePatientProfile, D3FeatureIntent

FEATURES = tuple(key for key, _ in D3FeatureIntent.FEATURES)
VERSION = "d3-candidate-1"
LABELS = {
    "fr": {"photo": "Photo IA", "companion": "Compagnon IA", "habits": "Apprentissage de mes habitudes"},
    "ar": {"photo": "تحليل الصور بالذكاء الاصطناعي", "companion": "المساعد الذكي", "habits": "تعلم عاداتي"},
    "en": {"photo": "Photo AI", "companion": "AI companion", "habits": "Learning my habits"},
}
SUFFIX = {
    "fr": "Préférence future uniquement. Aucun envoi ni activation IA. Retrait possible à tout moment.",
    "ar": "تفضيل مستقبلي فقط. لا إرسال للبيانات ولا تفعيل للذكاء الاصطناعي. يمكن التراجع في أي وقت.",
    "en": "Future preference only. No data transfer or AI activation. You may withdraw at any time.",
}


def notice_for(feature, locale):
    if feature not in FEATURES or locale not in LABELS:
        raise ValueError("Unsupported feature or locale")
    text = LABELS[locale][feature] + " — " + SUFFIX[locale]
    digest = sha256("\n".join((VERSION, feature, locale, text)).encode("utf-8")).hexdigest()
    return {"version": VERSION, "locale": locale, "hash": digest, "text": text}


def _owner(patient):
    if not isinstance(patient, User) or not patient.is_authenticated or not patient.is_active or patient.pk is None:
        raise ValueError("Authenticated owner required")
    return patient.pk


def _current_receipt(owner_id, profile):
    if profile is None or not profile_has_current_consent(profile):
        return None
    return AIConsentReceipt.objects.filter(
        patient_id=owner_id, revoked_at__isnull=True,
        notice_version=profile.ai_consent_notice_version,
        notice_hash=profile.ai_consent_notice_hash,
        notice_locale=profile.ai_consent_notice_locale,
        granted_at=profile.ai_consent_given_at,
    ).order_by("-id").first()


def _status(feature, row, receipt):
    enabled = bool(row and row.intent_enabled and receipt and row.global_receipt_id == receipt.pk)
    return {
        "feature": feature,
        "intent_enabled": enabled,
        "revision": row.revision if row else 0,
        "activation_available": False,
        "external_ai_authorized": False,
    }


def read_feature_intent_envelope(patient):
    owner_id = _owner(patient)
    profile = BasePatientProfile.objects.filter(patient_id=owner_id).first()
    receipt = _current_receipt(owner_id, profile)
    rows = {row.feature: row for row in D3FeatureIntent.objects.filter(patient_id=owner_id)}
    return {
        "global_receipt_id": receipt.pk if receipt else None,
        "features": [_status(feature, rows.get(feature), receipt) for feature in FEATURES],
    }


def read_feature_intents(patient):
    return read_feature_intent_envelope(patient)["features"]


@transaction.atomic
def record_feature_intent(patient, *, feature, enabled, expected_revision, notice=None, expected_global_receipt_id=None):
    owner_id = _owner(patient)
    if feature not in FEATURES or type(enabled) is not bool or type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Invalid feature intent")
    # Serialize same-owner intent requests, including the first insert; global
    # consent changes serialize on the profile row, as in account.py.
    User.objects.select_for_update().get(pk=owner_id, is_active=True)
    profile = BasePatientProfile.objects.select_for_update().filter(patient_id=owner_id).first()
    receipt = _current_receipt(owner_id, profile)
    row = D3FeatureIntent.objects.filter(patient_id=owner_id, feature=feature).first()
    if expected_revision != (row.revision if row else 0):
        raise ValueError("Stale intent revision")
    if enabled:
        if receipt is None or not isinstance(notice, dict):
            raise ValueError("Current global receipt and exact feature notice required")
        if expected_global_receipt_id is not None and receipt.pk != expected_global_receipt_id:
            raise ValueError("Stale global consent receipt")
        expected = notice_for(feature, notice.get("locale"))
        if notice != expected:
            raise ValueError("Feature notice mismatch")
    else:
        expected = {"version": "", "hash": "", "locale": ""}
    if row is None:
        row = D3FeatureIntent(patient_id=owner_id, feature=feature)
    row.intent_enabled = enabled
    row.revision = expected_revision + 1
    row.global_receipt = receipt if enabled else None
    row.notice_version = expected["version"]
    row.notice_hash = expected["hash"]
    row.notice_locale = expected["locale"]
    row.save()
    return _status(feature, row, receipt)
