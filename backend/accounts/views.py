from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import Organization, UserOrganization
from .serializers import OrganizationSerializer, UserSerializer, EmailOrUsernameTokenObtainPairSerializer


class OrganizationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        org_ids = UserOrganization.objects.filter(user=user).values_list("organization_id", flat=True)
        return Organization.objects.filter(id__in=org_ids)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class EmailOrUsernameTokenObtainPairView(TokenObtainPairView):
    serializer_class = EmailOrUsernameTokenObtainPairSerializer
    throttle_scope = "login"
