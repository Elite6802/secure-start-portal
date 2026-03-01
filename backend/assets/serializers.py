from rest_framework import serializers
from .models import Asset


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = [
            "id",
            "organization",
            "name",
            "asset_type",
            "identifier",
            "risk_level",
            "last_scanned_at",
            "owner_team",
            "owner_contact",
            "tags",
            "high_risk_ssrf_authorized",
            "high_risk_ssrf_authorization_reference",
            "high_risk_ssrf_authorization_notes",
            "created_at",
        ]
