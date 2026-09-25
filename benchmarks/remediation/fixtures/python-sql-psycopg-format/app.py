"""Ticket search for the support console."""
import psycopg


def find_tickets(cursor, status):
    sql = "SELECT id, subject FROM tickets WHERE status = '%s'" % status
    cursor.execute(sql)
    return cursor.fetchall()


def connect(dsn):
    return psycopg.connect(dsn)
