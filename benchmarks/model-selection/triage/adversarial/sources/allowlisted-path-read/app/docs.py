import os

from flask import Flask, abort, request

app = Flask(__name__)

DOCS_DIR = os.path.join(os.path.dirname(__file__), "docs")
ALLOWED_DOCS = {"terms.txt", "privacy.txt", "licenses.txt"}


@app.route("/docs")
def read_doc():
    if request.args.get("name") not in ALLOWED_DOCS:
        abort(404)
    with open(os.path.join(DOCS_DIR, request.args.get("name")), encoding="utf-8") as handle:
        return handle.read()
