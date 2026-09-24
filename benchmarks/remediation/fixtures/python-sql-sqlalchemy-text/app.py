"""Read model for the analytics dashboard."""
from sqlalchemy import create_engine, text

ENGINE = create_engine("sqlite://")


def revenue_by_region(region):
    statement = text("SELECT region, SUM(total) FROM orders WHERE region = '" + region + "' GROUP BY region")
    return ENGINE.execute(statement).fetchall()
