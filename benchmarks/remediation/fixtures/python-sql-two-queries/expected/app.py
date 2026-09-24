"""Customer console queries. Two statements here build SQL from the account id."""
import sqlite3


def open_database(path):
    return sqlite3.connect(path)


def contacts_for_account(conn, account):
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM contacts WHERE account = ?", (account,))
    return cursor.fetchall()


def notes_for_account(conn, account):
    cursor = conn.cursor()
    cursor.execute("SELECT id, body FROM notes WHERE account = ?", (account,))
    return cursor.fetchall()
