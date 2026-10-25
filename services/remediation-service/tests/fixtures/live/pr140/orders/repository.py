import sqlite3
import subprocess
from pathlib import Path

DB_PATH = "orders.db"
EXPORT_ROOT = Path("/srv/exports")


def find_orders_by_customer(customer_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, total FROM orders WHERE customer = '" + customer_name + "'")
    return cursor.fetchall()


def archive_export(report_name):
    subprocess.run("tar czf /srv/archive/" + report_name + ".tgz /srv/exports/" + report_name, shell=True)


def read_export(filename):
    with open(EXPORT_ROOT / filename) as handle:
        return handle.read()
