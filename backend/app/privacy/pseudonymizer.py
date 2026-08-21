import hashlib
import hmac


class Pseudonymizer:
    """One-way stable pseudonyms. Keep the input identity mapping outside analytics."""

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode("utf-8")

    def identity_id(self, sid: str) -> str:
        digest = hmac.new(self._secret, sid.encode("utf-8"), hashlib.sha256).hexdigest()[:10].upper()
        return f"USR-{digest}"
