"""Log rotation helpers for the operations cron job."""
import os


def archive_log(path):
    os.system("gzip --force {}".format(path))
    return path + ".gz"
