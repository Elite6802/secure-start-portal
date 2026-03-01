import uuid
from django.conf import settings
from django.db import migrations, models
from django.db.models import JSONField


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="ActivityLog",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("action", models.CharField(max_length=255)),
                ("timestamp", models.DateTimeField()),
                ("metadata", JSONField(blank=True, default=dict)),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="activity_logs", to="accounts.organization")),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name="activity_logs", to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
