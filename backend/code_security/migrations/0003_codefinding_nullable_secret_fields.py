from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("code_security", "0002_codefinding_secret_fields"),
    ]

    operations = [
        migrations.AlterField(
            model_name="codefinding",
            name="secret_type",
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
        migrations.AlterField(
            model_name="codefinding",
            name="file_path",
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name="codefinding",
            name="masked_value",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="codefinding",
            name="rationale",
            field=models.TextField(blank=True, null=True),
        ),
    ]
