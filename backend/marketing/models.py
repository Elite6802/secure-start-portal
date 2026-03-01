from django.db import models
from core.models import BaseModel


class ContactRequest(BaseModel):
    name = models.CharField(max_length=160)
    email = models.EmailField()
    company = models.CharField(max_length=180, blank=True)
    message = models.TextField()
    source_page = models.CharField(max_length=120, blank=True)

    def __str__(self) -> str:
        return f"ContactRequest {self.email}"
