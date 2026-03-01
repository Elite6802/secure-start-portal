from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scans", "0005_scan_metadata"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="failure_reason",
            field=models.TextField(blank=True),
        ),
    ]
