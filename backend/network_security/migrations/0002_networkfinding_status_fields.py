from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("network_security", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkfinding",
            name="status",
            field=models.CharField(
                choices=[("open", "Open"), ("resolved", "Resolved")],
                default="open",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="networkfinding",
            name="resolved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
