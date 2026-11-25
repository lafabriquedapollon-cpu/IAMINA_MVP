"""Default-denied HTTP candidate. A preference cannot authorize AI egress."""
from django.conf import settings
from ninja import Router
from ninja.errors import HttpError
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr

from core.d3_feature_intents import FEATURES, notice_for, read_feature_intent_envelope, record_feature_intent
from core.native_auth import NativeTokenError, verify_native_token

router = Router(tags=["d3-feature-intents"])


class NoticeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: StrictStr
    locale: StrictStr
    hash: StrictStr
    text: StrictStr


class IntentSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool
    expected_revision: StrictInt
    expected_global_receipt_id: StrictInt | None = None
    notice: NoticeSchema | None = None


class FeatureStatus(BaseModel):
    feature: str
    intent_enabled: bool
    revision: int
    activation_available: bool
    external_ai_authorized: bool


class Envelope(BaseModel):
    global_receipt_id: int | None
    features: list[FeatureStatus]
    notices: dict[str, NoticeSchema]


def _owner(request):
    # Not exposed in normal builds. Even on test activation require an active
    # sovereign bearer, not just a cookie, client-supplied patient ID or Firebase.
    if getattr(settings, "D3_FEATURE_INTENTS_API_ENABLED", False) is not True:
        raise HttpError(404, "Feature unavailable")
    token = request.headers.get("Authorization", "")
    if not token.startswith("Bearer iamina."):
        raise HttpError(401, "Native identity required")
    try:
        owner = verify_native_token(token.removeprefix("Bearer "))
    except NativeTokenError as exc:
        raise HttpError(401, "Native identity required") from exc
    if not request.user.is_authenticated or owner.pk != request.user.pk:
        raise HttpError(401, "Conflicting identity")
    return owner


@router.get("/account/ai-feature-intents", response=Envelope)
def get_feature_intents(request, locale: str = "fr"):
    owner = _owner(request)
    try:
        notices = {feature: notice_for(feature, locale) for feature in FEATURES}
    except ValueError as exc:
        raise HttpError(422, "Unsupported locale") from exc
    return {**read_feature_intent_envelope(owner), "notices": notices}


@router.put("/account/ai-feature-intents/{feature}", response=FeatureStatus)
def put_feature_intent(request, feature: str, data: IntentSchema):
    owner = _owner(request)
    if feature not in FEATURES or data.expected_revision < 0:
        raise HttpError(422, "Invalid intent")
    if data.enabled and (data.expected_global_receipt_id is None or data.expected_global_receipt_id <= 0 or data.notice is None):
        raise HttpError(422, "Current receipt and exact notice required")
    if not data.enabled and (data.notice is not None or data.expected_global_receipt_id is not None):
        raise HttpError(422, "Withdrawal must not include a grant claim")
    try:
        return record_feature_intent(
            owner, feature=feature, enabled=data.enabled,
            expected_revision=data.expected_revision,
            expected_global_receipt_id=data.expected_global_receipt_id,
            notice=data.notice.model_dump() if data.notice else None,
        )
    except ValueError as exc:
        raise HttpError(409 if str(exc).startswith("Stale") else 422, "Intent rejected") from exc
