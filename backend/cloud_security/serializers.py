from rest_framework import serializers
from .models import CloudAccount, CloudFinding


class CloudAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = CloudAccount
        fields = [
            "id",
            "organization",
            "created_by",
            "provider",
            "name",
            "aws_account_id",
            "aws_role_arn",
            "aws_external_id",
            "azure_tenant_id",
            "azure_client_id",
            "azure_subscription_id",
            "gcp_project_id",
            "status",
            "last_validated_at",
            "last_error",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_by",
            "status",
            "last_validated_at",
            "last_error",
            "created_at",
            "updated_at",
        ]


class CloudAccountSecretsSerializer(serializers.ModelSerializer):
    azure_client_secret = serializers.CharField(write_only=True, required=False)
    gcp_service_account_json = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = CloudAccount
        fields = [
            "id",
            "azure_client_secret",
            "gcp_service_account_json",
        ]


class CloudFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = CloudFinding
        fields = [
            "id",
            "organization",
            "cloud_account",
            "asset",
            "scan_job",
            "service_request",
            "title",
            "severity",
            "status",
            "resolved_at",
            "description",
            "remediation",
            "evidence",
            "compliance",
            "cvss_vector",
            "created_at",
        ]
        read_only_fields = fields
