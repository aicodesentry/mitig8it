"""Ticket search for the support console."""
import psycopg


def find_tickets(cursor, status):
    sql = "SELECT id, subject FROM tickets WHERE status = %s"
    cursor.execute(sql, (status,))
    return cursor.fetchall()


def connect(dsn):
    return psycopg.connect(dsn)
