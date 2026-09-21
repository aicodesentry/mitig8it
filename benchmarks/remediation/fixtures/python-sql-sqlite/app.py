import sqlite3


def open_database(path):
    return sqlite3.connect(path)


def find_user(conn, email):
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users WHERE email = '" + email + "'")
    return cursor.fetchone()
