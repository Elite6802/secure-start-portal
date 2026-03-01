from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0004_add_scanjob_service_request"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
