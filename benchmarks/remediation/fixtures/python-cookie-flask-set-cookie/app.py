import secrets

from flask import Flask, make_response

app = Flask(__name__)


@app.route("/remember")
def remember():
    response = make_response("remembered")
    response.set_cookie("remember_token", secrets.token_hex(16), max_age=3600, secure=False)
    return response
