"""Warehouse database configuration."""
import os

DATABASE = {
    "host": "warehouse.internal",
    "port": 5432,
    "user": "warehouse_app",
    "password": os.environ["WAREHOUSE_DB_PASSWORD"],
    "database": "warehouse",
}


def dsn():
    return "postgresql://{user}:{password}@{host}:{port}/{database}".format(**DATABASE)
