import hashlib as hl
import os

SALT = os.environ.get("APP_SALT", "")


def hash_pwd(pwd):
    return hl.md5(pwd.encode("utf-8")).hexdigest()


def is_valid(pwd, expected):
    return expected == hash_pwd(pwd)
