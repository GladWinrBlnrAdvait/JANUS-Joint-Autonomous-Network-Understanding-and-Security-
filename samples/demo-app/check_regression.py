"""Functional (regression) check for the demo app. Run by the validation layer, not by the repo's pytest."""
import pytest

import app


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "DB_PATH", str(tmp_path / "check.db"))
    app.init_db()


def test_valid_login_returns_role():
    assert app.login("admin", "change-me") == "admin"


def test_wrong_password_and_unknown_user_are_rejected():
    assert app.login("admin", "wrong") is None
    assert app.login("nobody", "change-me") is None


def test_other_functions_still_work():
    assert app.list_users() == [("admin", "admin")]
    assert app.health() == {"status": "ok"}
