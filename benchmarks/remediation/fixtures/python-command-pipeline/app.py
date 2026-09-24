"""Error summaries for the operations dashboard."""
import subprocess


def error_counts(service):
    return subprocess.check_output("journalctl -u " + service + " | grep ERROR | wc -l", shell=True, text=True)
