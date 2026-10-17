import hashlib as hl
import os
import hmac

SALT = os.environ.get("APP_SALT", "")


def hash_pwd(pwd):
    salt = os.urandom(16)
    digest = hl.scrypt(pwd.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password_hash(pwd, stored):
    scheme, _, rest = str(stored).partition("$")
    salt, _, expected = rest.partition("$")
    if scheme != "scrypt" or not salt or not expected:
        return False
    try:
        digest = hl.scrypt(pwd.encode("utf-8"), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), expected)


def is_valid(pwd, expected):
    return verify_password_hash(pwd, expected)
