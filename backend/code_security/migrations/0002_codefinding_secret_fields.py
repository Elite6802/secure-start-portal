from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("code_security", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="codefinding",
            name="secret_type",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="codefinding",
            name="file_path",
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.AddField(
            model_name="codefinding",
            name="line_number",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="codefinding",
            name="masked_value",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="codefinding",
            name="confidence_score",
            field=models.PositiveSmallIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="codefinding",
            name="rationale",
            field=models.TextField(blank=True),
        ),
    ]
