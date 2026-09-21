# Test file for SCRUM-87, 97, 99, 88
import os

# SQL Injection vulnerability
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"

# Insecure eval
def process_input(user_input):
    result = eval(user_input)
    return result

from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route("/profile/favirites/", methods=["POST"])
def favorites_route():
    favorites = etree.fromstring(request.data)  # equivalent to parsexml
    addToFavorites(favorite)  # note: still uses 'favorite' as in original code
    return "", 200

def addToFavorites(favorite):
    # placeholder function
    pass

if __name__ == "__main__":
    app.run()


