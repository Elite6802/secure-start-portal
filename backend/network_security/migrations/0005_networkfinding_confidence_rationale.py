from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("network_security", "0004_networkfinding_evidence"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkfinding",
            name="confidence_score",
            field=models.PositiveSmallIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="networkfinding",
            name="rationale",
            field=models.TextField(blank=True),
        ),
    ]
