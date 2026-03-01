from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("reports", "0001_initial"),
        ("service_requests", "0001_initial"),
        ("scans", "0004_add_scanjob_service_request"),
    ]

    operations = [
        migrations.AddField(
            model_name="report",
            name="service_request",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="reports",
                to="service_requests.servicerequest",
            ),
        ),
        migrations.AddField(
            model_name="report",
            name="scan_job",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="reports",
                to="scans.scanjob",
            ),
        ),
    ]
