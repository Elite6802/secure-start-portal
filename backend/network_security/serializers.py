from rest_framework import serializers
from core.ai_explanations import explain_network_finding
from .models import NetworkAsset, NetworkFinding


class NetworkAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkAsset
        fields = ["id", "organization", "asset", "network_type", "created_at"]


class NetworkFindingSerializer(serializers.ModelSerializer):
    ai_explanation = serializers.SerializerMethodField()

    def get_ai_explanation(self, obj):
        request = self.context.get("request")
        role = getattr(request.user, "role", None) if request and request.user else None
        return explain_network_finding(obj, role=role)

    class Meta:
        model = NetworkFinding
        fields = [
            "id",
            "network_asset",
            "finding_type",
            "severity",
            "status",
            "resolved_at",
            "confidence_score",
            "summary",
            "recommendation",
            "rationale",
            "evidence",
            "cvss_vector",
            "ai_explanation",
            "scan_job",
            "service_request",
            "created_at",
        ]
