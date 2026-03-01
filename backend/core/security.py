import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _load_key() -> bytes:
    key = getattr(settings, "CLOUD_CREDENTIALS_KEY", "") or os.getenv("CLOUD_CREDENTIALS_KEY", "")
    if not key:
        # Fall back to derived key from SECRET_KEY for dev convenience (still encrypted).
        raw = settings.SECRET_KEY.encode("utf-8")
        return base64.urlsafe_b64encode(raw[:32].ljust(32, b"_"))
    if isinstance(key, str):
        return key.encode("utf-8")
    return key


def _fernet() -> Fernet:
    return Fernet(_load_key())


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    token = _fernet().encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""
