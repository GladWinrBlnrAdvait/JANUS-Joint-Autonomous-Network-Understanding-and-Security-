"""Intentionally vulnerable demo application for JANUS (lab use only)."""

import sqlite3

DB_PATH = "demo.db"






def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, role TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', 'change-me', 'admin')")
    conn.commit()
    conn.close()


def list_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows


def health():
    return {"status": "ok"}


def login(username, password):
    """Return the user's role if the credentials match, else None."""
    conn = get_connection()
    cursor = conn.cursor()
    query = f"SELECT role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


if __name__ == "__main__":
    init_db()
    print(login("admin", "change-me"))
