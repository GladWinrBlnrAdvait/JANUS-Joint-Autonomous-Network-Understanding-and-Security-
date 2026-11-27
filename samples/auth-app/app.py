"""Intentionally vulnerable password helper for JANUS (lab use only)."""

import hashlib


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password, stored):
    return hash_password(password) == stored
