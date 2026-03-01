from django.urls import path
from .views import ContactRequestCreateView, ContactEmailTestView


urlpatterns = [
    path("contact-requests/", ContactRequestCreateView.as_view(), name="contact-requests"),
    path("contact-requests/test-email/", ContactEmailTestView.as_view(), name="contact-requests-test-email"),
]
