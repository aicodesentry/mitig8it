"""Monthly report downloads."""
import os

from flask import Flask, request, send_file

app = Flask(__name__)
REPORT_DIR = "/srv/reports"


@app.route("/reports")
def download_report():
    name = request.args.get("name")
    return send_file(os.path.join(REPORT_DIR, name))
