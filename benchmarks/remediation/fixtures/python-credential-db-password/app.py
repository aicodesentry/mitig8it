"""Warehouse database configuration."""

DATABASE = {
    "host": "warehouse.internal",
    "port": 5432,
    "user": "warehouse_app",
    "password": "Pa55w0rd-warehouse-2026",
    "database": "warehouse",
}


def dsn():
    return "postgresql://{user}:{password}@{host}:{port}/{database}".format(**DATABASE)
