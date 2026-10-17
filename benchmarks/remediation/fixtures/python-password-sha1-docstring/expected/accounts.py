import hashlib
import hmac
import os


def hash_password(password):
    """Returns the value stored in the accounts table."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password_hash(password, stored):
    scheme, _, rest = str(stored).partition("$")
    salt, _, expected = rest.partition("$")
    if scheme != "scrypt" or not salt or not expected:
        return False
    try:
        digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), expected)


def check_login(stored, password):
    if not verify_password_hash(password, stored):
        return False
    return True
