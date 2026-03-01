from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("reports", "0002_report_links"),
    ]

    operations = [
        migrations.AddField(
            model_name="report",
            name="client_visible",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="report",
            name="sent_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
