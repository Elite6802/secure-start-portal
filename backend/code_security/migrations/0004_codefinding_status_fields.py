from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("code_security", "0003_codefinding_nullable_secret_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="codefinding",
            name="status",
            field=models.CharField(
                choices=[("open", "Open"), ("resolved", "Resolved")],
                default="open",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="codefinding",
            name="resolved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
