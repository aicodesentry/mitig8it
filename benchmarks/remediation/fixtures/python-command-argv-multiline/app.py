"""Nightly backup jobs."""
import subprocess


def backup_command(source, destination):
    return (
        "tar -czf "
        + destination
        + " "
        + source
    )


def run_backup(source, destination):
    subprocess.check_call(backup_command(source, destination), shell=True)
    return destination
