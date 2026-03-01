from django.db import migrations


def backfill_cloud_metadata(apps, schema_editor):
    Report = apps.get_model("reports", "Report")

    queryset = Report.objects.filter(service_request__cloud_account__isnull=False).select_related(
        "service_request__cloud_account"
    )
    for report in queryset.iterator():
        metadata = report.metadata or {}
        if not isinstance(metadata, dict):
            metadata = {}
        if (
            "cloud_account_id" in metadata
            and "cloud_account_name" in metadata
            and "cloud_provider" in metadata
        ):
            continue
        service_request = report.service_request
        if not service_request or not service_request.cloud_account:
            continue
        account = service_request.cloud_account
        metadata.update(
            {
                "cloud_account_id": str(account.id),
                "cloud_account_name": account.name,
                "cloud_provider": account.provider,
            }
        )
        report.metadata = metadata
        report.save(update_fields=["metadata"])


def noop_reverse(apps, schema_editor):
    return


class Migration(migrations.Migration):
    dependencies = [
        ("reports", "0005_alter_report_scope"),
        ("service_requests", "0005_servicerequest_cloud_account_and_more"),
        ("cloud_security", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(backfill_cloud_metadata, reverse_code=noop_reverse),
    ]
