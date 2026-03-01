import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Report",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("is_deleted", models.BooleanField(default=False)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("scope", models.CharField(choices=[("web", "Web"), ("code", "Code"), ("network", "Network"), ("combined", "Combined")], default="combined", max_length=20)),
                ("summary", models.TextField()),
                ("generated_at", models.DateTimeField()),
                ("file_path", models.CharField(blank=True, max_length=255)),
                ("organization", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="reports", to="accounts.organization")),
            ],
        ),
    ]
