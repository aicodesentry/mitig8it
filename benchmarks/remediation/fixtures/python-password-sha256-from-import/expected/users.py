from hashlib import sha256
import hashlib
import hmac
import os


def make_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password_hash(password, stored):
    scheme, _, rest = str(stored).partition("$")
    salt, _, expected = rest.partition("$")
    if scheme != "scrypt" or not salt or not expected:
        return False
    try:
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), expected)


def authenticate(user, password):
    return verify_password_hash(password, user)


def rotate(user, old, new):
    if not verify_password_hash(old, user):
        raise ValueError("old password does not match")
    return make_password(new)
