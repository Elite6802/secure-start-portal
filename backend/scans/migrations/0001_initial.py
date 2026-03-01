import uuid
from django.db import migrations, models
from django.db.models import JSONField


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
        ("assets", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Scan",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("scan_type", models.CharField(choices=[("web", "Web"), ("api", "API"), ("code", "Code"), ("network", "Network"), ("infrastructure", "Infrastructure")], max_length=30)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed")], default="pending", max_length=20)),
                ("severity_summary", JSONField(blank=True, default=dict)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("asset", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="scans", to="assets.asset")),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="scans", to="accounts.organization")),
            ],
        ),
    ]
