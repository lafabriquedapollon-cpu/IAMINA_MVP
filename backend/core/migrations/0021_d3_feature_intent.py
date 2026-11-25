"""D3 preference storage only. No legacy consent backfill or activation."""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0020_d2_notification_center"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="D3FeatureIntent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("feature", models.CharField(choices=[("photo", "Photo AI"), ("companion", "AI companion"), ("habits", "Habit learning")], max_length=16)),
                ("intent_enabled", models.BooleanField(default=False)),
                ("revision", models.PositiveIntegerField(default=0)),
                ("notice_version", models.CharField(blank=True, default="", max_length=32)),
                ("notice_hash", models.CharField(blank=True, default="", max_length=64)),
                ("notice_locale", models.CharField(blank=True, default="", max_length=8)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("global_receipt", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="core.aiconsentreceipt")),
                ("patient", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="d3_feature_intents", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "constraints": [
                    models.UniqueConstraint(fields=("patient", "feature"), name="core_d3_intent_owner_feature"),
                    models.CheckConstraint(condition=models.Q(feature__in=("photo", "companion", "habits")), name="core_d3_intent_known_feature"),
                ],
            },
        ),
    ]
