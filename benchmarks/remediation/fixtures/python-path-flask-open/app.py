"""Invoice PDF downloads."""
import os

from flask import Flask, request

app = Flask(__name__)
INVOICE_DIR = "/srv/invoices"


@app.route("/invoices")
def download_invoice():
    name = request.args.get("name")
    path = os.path.join(INVOICE_DIR, name)
    with open(path, "rb") as handle:
        return handle.read()
