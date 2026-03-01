import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_initial"),
        ("assets", "0001_initial"),
        ("code_security", "0001_initial"),
        ("scans", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="ScanJob",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("scan_type", models.CharField(choices=[("code", "Code"), ("network", "Network"), ("web", "Web")], max_length=20)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed")], default="queued", max_length=20)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("asset", models.ForeignKey(blank=True, null=True, on_delete=models.deletion.CASCADE, related_name="scan_jobs", to="assets.asset")),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name="scan_jobs", to=settings.AUTH_USER_MODEL)),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="scan_jobs", to="accounts.organization")),
                ("repository", models.ForeignKey(blank=True, null=True, on_delete=models.deletion.CASCADE, related_name="scan_jobs", to="code_security.coderepository")),
            ],
        ),
    ]
