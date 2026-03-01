import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
        ("assets", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="NetworkAsset",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("network_type", models.CharField(choices=[("internal", "Internal"), ("external", "External")], default="internal", max_length=20)),
                ("asset", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="network_assets", to="assets.asset")),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="network_assets", to="accounts.organization")),
            ],
        ),
        migrations.CreateModel(
            name="NetworkFinding",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("finding_type", models.CharField(choices=[("exposed_service", "Exposed Service"), ("segmentation_risk", "Segmentation Risk"), ("misconfiguration", "Misconfiguration")], max_length=50)),
                ("severity", models.CharField(choices=[("critical", "Critical"), ("high", "High"), ("moderate", "Moderate"), ("low", "Low")], max_length=20)),
                ("summary", models.CharField(max_length=255)),
                ("recommendation", models.TextField(blank=True)),
                ("network_asset", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="findings", to="network_security.networkasset")),
            ],
        ),
    ]
