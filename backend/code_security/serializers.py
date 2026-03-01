from rest_framework import serializers
from core.ai_explanations import explain_code_finding
from .models import CodeRepository, CodeFinding


class CodeRepositorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CodeRepository
        fields = ["id", "organization", "asset", "repo_url", "language", "created_at"]


class CodeFindingSerializer(serializers.ModelSerializer):
    ai_explanation = serializers.SerializerMethodField()

    def get_ai_explanation(self, obj):
        request = self.context.get("request")
        role = getattr(request.user, "role", None) if request and request.user else None
        return explain_code_finding(obj, role=role)

    class Meta:
        model = CodeFinding
        fields = [
            "id",
            "repository",
            "category",
            "severity",
            "status",
            "resolved_at",
            "title",
            "description",
            "remediation",
            "standard_mapping",
            "scan_job",
            "service_request",
            "secret_type",
            "file_path",
            "line_number",
            "masked_value",
            "confidence_score",
            "rationale",
            "cvss_vector",
            "ai_explanation",
            "created_at",
        ]
