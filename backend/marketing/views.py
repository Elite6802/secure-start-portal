import json
import urllib.request
from django.conf import settings
from django.core.mail import send_mail
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ContactRequest
from .serializers import ContactRequestSerializer


class ContactRequestCreateView(generics.CreateAPIView):
    queryset = ContactRequest.objects.all()
    serializer_class = ContactRequestSerializer
    permission_classes = [permissions.AllowAny]
    throttle_scope = "contact"

    def perform_create(self, serializer):
        contact = serializer.save()
        recipients = [getattr(settings, "CONTACT_INBOX_EMAIL", "")] if getattr(settings, "CONTACT_INBOX_EMAIL", "") else []
        subject = f"New security contact request from {contact.name}"
        body = (
            f"Name: {contact.name}\n"
            f"Email: {contact.email}\n"
            f"Company: {contact.company or '-'}\n"
            f"Source page: {contact.source_page or '-'}\n\n"
            f"Message:\n{contact.message}\n"
        )
        if recipients:
            send_mail(
                subject,
                body,
                getattr(settings, "DEFAULT_FROM_EMAIL", "security@aegis.local"),
                recipients,
                fail_silently=True,
            )

        confirmation_subject = getattr(settings, "CONTACT_CONFIRMATION_SUBJECT", "")
        confirmation_body_template = getattr(settings, "CONTACT_CONFIRMATION_BODY", "")
        if confirmation_subject and confirmation_body_template:
            confirmation_body = confirmation_body_template.format(
                name=contact.name,
                company=contact.company or "-",
                message=contact.message,
            )
            send_mail(
                confirmation_subject,
                confirmation_body,
                getattr(settings, "DEFAULT_FROM_EMAIL", "security@aegis.local"),
                [contact.email],
                fail_silently=True,
            )

        webhook_url = getattr(settings, "CONTACT_WEBHOOK_URL", "")
        if webhook_url:
            payload = json.dumps(
                {
                    "id": str(contact.id),
                    "name": contact.name,
                    "email": contact.email,
                    "company": contact.company,
                    "message": contact.message,
                    "source_page": contact.source_page,
                    "created_at": contact.created_at.isoformat(),
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except Exception:
                pass


class ContactEmailTestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if not (request.user and request.user.is_staff):
            return Response({"detail": "Admin access required."}, status=status.HTTP_403_FORBIDDEN)
        inbox = getattr(settings, "CONTACT_INBOX_EMAIL", "")
        if not inbox:
            return Response({"detail": "CONTACT_INBOX_EMAIL is not configured."}, status=status.HTTP_400_BAD_REQUEST)
        send_mail(
            "Aegis contact email test",
            "This is a test email from the Aegis platform.",
            getattr(settings, "DEFAULT_FROM_EMAIL", "security@aegis.local"),
            [inbox],
            fail_silently=False,
        )
        return Response({"status": "sent"})
