from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("cloud_security", "0003_cloudfinding_cvss_vector"),
    ]

    operations = [
        migrations.AddField(
            model_name="cloudfinding",
            name="status",
            field=models.CharField(
                choices=[("open", "Open"), ("resolved", "Resolved")],
                default="open",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="cloudfinding",
            name="resolved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

