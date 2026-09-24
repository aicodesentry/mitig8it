"""Monthly report downloads."""
import os

from flask import Flask, request, send_file, abort

app = Flask(__name__)
REPORT_DIR = "/srv/reports"


@app.route("/reports")
def download_report():
    name = request.args.get("name")
    base_dir = os.path.realpath(REPORT_DIR)
    target = os.path.realpath(os.path.join(base_dir, name))
    if target != base_dir and not target.startswith(base_dir + os.sep):
        abort(400)
    return send_file(target)
