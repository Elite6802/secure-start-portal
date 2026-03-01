from rest_framework import serializers
from .models import Incident


class IncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Incident
        fields = [
            "id",
            "organization",
            "severity",
            "status",
            "description",
            "detected_at",
            "resolved_at",
            "created_at",
        ]
