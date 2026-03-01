from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Organization, UserOrganization


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "name", "industry", "domain", "created_at"]


class UserOrganizationSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)

    class Meta:
        model = UserOrganization
        fields = ["id", "organization", "role", "is_primary", "created_at"]


class UserSerializer(serializers.ModelSerializer):
    memberships = UserOrganizationSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "memberships"]


class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        username = (attrs.get("username") or "").strip()
        password = attrs.get("password")

        user = None
        if username:
            user = User.objects.filter(email__iexact=username).first()
            if not user:
                user = User.objects.filter(username__iexact=username).first()

        if not user:
            raise AuthenticationFailed("User not found.")
        if not user.is_active:
            raise AuthenticationFailed("User inactive or deleted.")
        if not user.check_password(password):
            raise AuthenticationFailed("Invalid credentials.")

        refresh = self.get_token(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
