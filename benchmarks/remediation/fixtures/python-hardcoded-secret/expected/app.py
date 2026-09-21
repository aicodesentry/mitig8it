"""Client for the vendor billing API."""
import os

API_KEY = os.environ["API_KEY"]


def auth_headers():
    return {"Authorization": "Bearer " + API_KEY}
