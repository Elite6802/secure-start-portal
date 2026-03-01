from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("network_security", "0003_merge_20260207_1011"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkfinding",
            name="evidence",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
