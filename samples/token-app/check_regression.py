"""Functional check: signing and verifying still work (independent of which key is used)."""
import os

os.environ.setdefault("APP_SECRET_KEY", "check-key")

import app


def test_signature_is_stable_and_message_specific():
    assert app.sign("a") == app.sign("a")
    assert app.sign("a") != app.sign("b")
    assert len(app.sign("a")) == 64


def test_verify_roundtrip():
    assert app.verify("hello", app.sign("hello"))
    assert not app.verify("hello", app.sign("other"))
