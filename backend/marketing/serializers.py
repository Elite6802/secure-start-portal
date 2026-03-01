from rest_framework import serializers
from .models import ContactRequest


class ContactRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactRequest
        fields = [
            "id",
            "name",
            "email",
            "company",
            "message",
            "source_page",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]
