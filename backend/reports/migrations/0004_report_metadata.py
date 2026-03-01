from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("reports", "0003_report_visibility_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="report",
            name="metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
