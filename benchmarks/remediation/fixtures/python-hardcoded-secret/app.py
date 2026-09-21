"""Client for the vendor billing API."""

API_KEY = "sk-live-aaaaaaaaaaaaaaaa"


def auth_headers():
    return {"Authorization": "Bearer " + API_KEY}
