"""Log rotation helpers for the operations cron job."""
import os
import subprocess


def archive_log(path):
    subprocess.run(["gzip", "--force", path], check=True)
    return path + ".gz"
