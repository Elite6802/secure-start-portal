import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Asset",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("name", models.CharField(max_length=255)),
                ("asset_type", models.CharField(choices=[("domain", "Domain"), ("web_app", "Web Application"), ("api", "API"), ("cloud_resource", "Cloud Resource"), ("network_segment", "Network Segment"), ("ip_range", "IP Range"), ("code_repository", "Code Repository")], max_length=50)),
                ("identifier", models.CharField(max_length=512)),
                ("risk_level", models.CharField(choices=[("critical", "Critical"), ("moderate", "Moderate"), ("low", "Low")], default="low", max_length=20)),
                ("last_scanned_at", models.DateTimeField(blank=True, null=True)),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="assets", to="accounts.organization")),
            ],
        ),
    ]
