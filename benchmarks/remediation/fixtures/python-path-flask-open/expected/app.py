"""Invoice PDF downloads."""
import os

from flask import Flask, request, abort

app = Flask(__name__)
INVOICE_DIR = "/srv/invoices"


@app.route("/invoices")
def download_invoice():
    name = request.args.get("name")
    base_dir = os.path.realpath(INVOICE_DIR)
    path = os.path.realpath(os.path.join(base_dir, name))
    if path != base_dir and not path.startswith(base_dir + os.sep):
        abort(400)
    with open(path, "rb") as handle:
        return handle.read()
