import uuid
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("accounts", "0006_organization_scan_policy_inventory_expectations"),
    ]

    operations = [
        migrations.CreateModel(
            name="FindingDisposition",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("object_id", models.UUIDField()),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "Open"),
                            ("resolved", "Resolved"),
                            ("accepted_risk", "Accepted Risk"),
                            ("suppressed", "Suppressed"),
                        ],
                        default="open",
                        max_length=32,
                    ),
                ),
                ("justification", models.TextField(blank=True)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                (
                    "content_type",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="contenttypes.contenttype"),
                ),
                (
                    "organization",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="finding_dispositions", to="accounts.organization"),
                ),
                (
                    "updated_by",
                    models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="finding_dispositions", to="accounts.user"),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["organization", "status"], name="triage_find_organiza_5b6a06_idx"),
                    models.Index(fields=["content_type", "object_id"], name="triage_find_content__f8f76a_idx"),
                    models.Index(fields=["expires_at"], name="triage_find_expires__a2fe01_idx"),
                ],
                "unique_together": {("content_type", "object_id")},
            },
        ),
    ]
