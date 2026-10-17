import hashlib


def hash_password(password):
    """Returns the value stored in the accounts table."""
    # Hex so it fits the existing VARCHAR column.
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest()
    return digest


def check_login(stored, password):
    if hash_password(password) != stored:
        return False
    return True
