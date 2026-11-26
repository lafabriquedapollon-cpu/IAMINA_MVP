from django.contrib.auth.models import User
from django.db import models

from core.models.ai_consent_receipt import AIConsentReceipt


class D3FeatureIntent(models.Model):
    """Future feature preference only; never a provider authorization."""

    FEATURES = (
        ("photo", "Photo AI"),
        ("companion", "AI companion"),
        ("habits", "Habit learning"),
    )
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="d3_feature_intents")
    feature = models.CharField(max_length=16, choices=FEATURES)
    intent_enabled = models.BooleanField(default=False)
    revision = models.PositiveIntegerField(default=0)
    global_receipt = models.ForeignKey(AIConsentReceipt, null=True, blank=True, on_delete=models.SET_NULL)
    notice_version = models.CharField(max_length=32, blank=True, default="")
    notice_hash = models.CharField(max_length=64, blank=True, default="")
    notice_locale = models.CharField(max_length=8, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "core"
        constraints = [
            models.UniqueConstraint(fields=("patient", "feature"), name="core_d3_intent_owner_feature"),
            models.CheckConstraint(condition=models.Q(feature__in=("photo", "companion", "habits")), name="core_d3_intent_known_feature"),
        ]
