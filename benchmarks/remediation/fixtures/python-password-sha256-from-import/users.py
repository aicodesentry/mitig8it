from hashlib import sha256


def make_password(password):
    password_hash = sha256(password.encode()).hexdigest()
    return password_hash


def authenticate(user, password):
    return make_password(password) == user


def rotate(user, old, new):
    if make_password(old) != user:
        raise ValueError("old password does not match")
    return make_password(new)
