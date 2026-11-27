"""Functional check: normal notes still work."""
import pytest

import app


def test_reads_a_normal_note():
    assert app.read_note("welcome.txt").strip() == "Welcome to JANUS notes."


def test_missing_note_still_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        app.read_note("does-not-exist.txt")


def test_listing_works():
    assert "welcome.txt" in app.list_notes()
