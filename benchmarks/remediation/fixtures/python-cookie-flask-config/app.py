from flask import Flask

app = Flask(__name__)
app.config["SESSION_COOKIE_NAME"] = "tracker_session"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = False


@app.route("/health")
def health():
    return "ok"
