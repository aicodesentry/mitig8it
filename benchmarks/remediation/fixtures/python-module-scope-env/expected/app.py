"""Nightly backup job.

The cron entry imports this module and nothing else: the command runs at import, so there is no
function a generated test could call, and the only input it has is the environment.
"""
import os
import subprocess

TARGET = os.environ["BACKUP_TARGET"]
RESULT = subprocess.run(["rsync", "-a", "/var/data", TARGET])
