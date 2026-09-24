"""Audit log lookups. The statement is already parameterized."""
import sqlite3


def open_database(path):
    return sqlite3.connect(path)


def events_for_actor(conn, actor):
    cursor = conn.cursor()
    cursor.execute("SELECT id, action FROM audit_events WHERE actor = ?", (actor,))
    return cursor.fetchall()
