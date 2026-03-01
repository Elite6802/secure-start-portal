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
            name="CodeRepository",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("repo_url", models.URLField()),
                ("language", models.CharField(blank=True, max_length=120)),
                ("asset", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="code_repository", to="assets.asset")),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="code_repositories", to="accounts.organization")),
            ],
        ),
        migrations.CreateModel(
            name="CodeFinding",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("category", models.CharField(choices=[("sast", "SAST"), ("dependency", "Dependency"), ("secrets", "Secrets")], max_length=30)),
                ("severity", models.CharField(choices=[("critical", "Critical"), ("high", "High"), ("moderate", "Moderate"), ("low", "Low")], max_length=20)),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField()),
                ("remediation", models.TextField(blank=True)),
                ("standard_mapping", JSONField(blank=True, default=list)),
                ("repository", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="findings", to="code_security.coderepository")),
            ],
        ),
    ]
