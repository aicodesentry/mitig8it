"""Attachment storage."""
import os

ATTACHMENT_DIR = "/srv/attachments"


def resolve_attachment(name):
    base_dir = os.path.realpath(ATTACHMENT_DIR)
    target = os.path.realpath(os.path.join(base_dir, name))
    if target != base_dir and not target.startswith(base_dir + os.sep):
        raise ValueError("path escapes base directory")
    return target
