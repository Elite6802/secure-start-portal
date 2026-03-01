from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0002_asset_high_risk_ssrf_authorization"),
    ]

    operations = [
        migrations.AddField(
            model_name="asset",
            name="owner_team",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="asset",
            name="owner_contact",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="asset",
            name="tags",
            field=models.JSONField(blank=True, default=list),
        ),
    ]

