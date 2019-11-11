import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

EXCEPTIONS = ["cipher.py", "cipher.exe"]


def encode(filename, fernet):
    if filename.endswith(".cipher"):
        raise Exception("can't encode an already encoded file")

    print("encoding '%s' now" % filename)

    with open(filename, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(filename, "wb") as f:
        f.write(encrypted)

    os.rename(filename, get_filename_without_extension(filename) + ".cipher")


def decode(filename, fernet):
    if filename.endswith(".txt"):
        raise Exception("can't decode an already decoded file")

    print("decoding '%s' now" % filename)

    with open(filename, "rb") as f:
        data = f.read()

    decrypted = fernet.decrypt(data)

    with open(filename, "wb") as f:
        f.write(decrypted)

    os.rename(filename, get_filename_without_extension(filename) + ".txt")


def decide(filename, f):
    if filename.endswith(".txt"):
        encode(filename, f)
    elif filename.endswith(".cipher"):
        decode(filename, f)


def get_filename_without_extension(filename):
    return os.path.splitext(filename)[0]


def get_key_from_password(password_provided):
    password = password_provided.encode()
    salt = b"\xec\xdc\xd5\xd2:J\xe2\x9e?\xd6\x1f\x0b^\xc4Hs"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


if __name__ == "__main__":
    try:
        os.system("color b")
        files = os.listdir(".")
        key = get_key_from_password(input("Insert key to encrypt/decrypt the files: "))
        fernet = Fernet(key)

        for file in files:
            if file not in EXCEPTIONS:
                decide(file, fernet)
    except InvalidToken:
        print("Invalid key!")
    except Exception as ex:
        print("Error: %s" % str(ex))
    finally:
        os.system('read -p "Press [Enter] key to continue..."')
