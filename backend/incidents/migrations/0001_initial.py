import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Incident",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("severity", models.CharField(choices=[("critical", "Critical"), ("high", "High"), ("moderate", "Moderate"), ("low", "Low")], max_length=20)),
                ("status", models.CharField(choices=[("open", "Open"), ("investigating", "Investigating"), ("resolved", "Resolved")], default="open", max_length=20)),
                ("description", models.TextField()),
                ("detected_at", models.DateTimeField()),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="incidents", to="accounts.organization")),
            ],
        ),
    ]
