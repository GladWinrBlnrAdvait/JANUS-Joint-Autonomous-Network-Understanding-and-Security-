"""Intentionally vulnerable token signer for JANUS (lab use only)."""

import hashlib
import hmac
import os

SECRET_KEY = "s3cr3t-hardcoded-key"


def sign(message):
    """Return an HMAC-SHA256 signature of the message."""
    return hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify(message, signature):
    return hmac.compare_digest(sign(message), signature)
