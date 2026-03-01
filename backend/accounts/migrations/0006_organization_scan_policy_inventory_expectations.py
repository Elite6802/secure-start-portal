from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0005_organization_scan_policy"),
    ]

    operations = [
        migrations.AddField(
            model_name="organizationscanpolicy",
            name="inventory_expectations",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="Optional expected inventory counts by category for completeness scoring.",
            ),
        ),
    ]

