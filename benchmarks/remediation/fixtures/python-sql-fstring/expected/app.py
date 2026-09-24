"""Invoice reporting queries."""
import sqlite3

DATABASE = "invoices.db"


def open_database():
    return sqlite3.connect(DATABASE)


def invoices_for_customer(conn, customer_id):
    cursor = conn.cursor()
    cursor.execute("SELECT id, total FROM invoices WHERE customer_id = ?", (customer_id,))
    return cursor.fetchall()
