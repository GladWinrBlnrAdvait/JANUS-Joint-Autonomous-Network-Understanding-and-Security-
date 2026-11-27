"""Intentionally vulnerable notes reader for JANUS (lab use only)."""

import os

NOTES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes")


def list_notes():
    return sorted(os.listdir(NOTES_DIR))


def read_note(name):
    """Return the text of a note stored in the notes folder."""
    path = os.path.join(NOTES_DIR, name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
