"""Attachment storage."""
import os

ATTACHMENT_DIR = "/srv/attachments"


def resolve_attachment(name):
    return os.path.join(ATTACHMENT_DIR, name)
