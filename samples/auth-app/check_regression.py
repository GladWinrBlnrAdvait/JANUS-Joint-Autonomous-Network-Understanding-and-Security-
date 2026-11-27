"""Functional check: hashing and verifying still work."""
import app


def test_verify_roundtrip():
    stored = app.hash_password("pw")
    assert app.verify_password("pw", stored)
    assert not app.verify_password("bad", stored)
    assert app.hash_password("pw") == app.hash_password("pw")
