import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

SALT = b"\xec\xdc\xd5\xd2:J\xe2\x9e?\xd6\x1f\x0b^\xc4Hs"
ENC_EXTENSION = "cipher"


def get_cur_file_wo_xtension():
    return str(__file__).split('\\')[-1:][0].split('.')[:-1]


EXCEPTIONS = (f"{get_cur_file_wo_xtension()}.py", f"{get_cur_file_wo_xtension()}.exe", "LICENSE", "README.md")


def is_windows():
    return os.name == 'nt'


def encode(filename, _fernet):
    if filename.endswith(f".{ENC_EXTENSION}"):
        raise Exception("can't encode an already encoded file")

    print("encoding '%s' now" % filename)

    with open(filename, "rb") as f:
        data = f.read()

    encrypted = _fernet.encrypt(data)

    with open(filename, "wb") as f:
        f.write(encrypted)

    os.rename(filename, get_filename_without_extension(filename) + f".{ENC_EXTENSION}")


def decode(filename, _fernet):
    if filename.endswith(".txt"):
        raise Exception("can't decode an already decoded file")

    print("decoding '%s' now" % filename)

    with open(filename, "rb") as f:
        data = f.read()

    decrypted = _fernet.decrypt(data)

    with open(filename, "wb") as f:
        f.write(decrypted)

    os.rename(filename, get_filename_without_extension(filename) + ".txt")


def decide(filename, f):
    if filename.endswith(".txt"):
        encode(filename, f)
    elif filename.endswith(f".{ENC_EXTENSION}"):
        decode(filename, f)


def get_filename_without_extension(filename):
    return os.path.splitext(filename)[0]


def get_key_from_password(password_provided):
    password = password_provided.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


if __name__ == "__main__":
    try:
        if is_windows():
            os.system("color b")  # Completely useless BTW
        files = os.listdir(".")
        pword = input("Insert key to encrypt/decrypt the file: ")
        confirm_pword = input("Confirm key: ")

        if pword != confirm_pword:
            raise InvalidToken("password and confirmation must be the same")

        key = get_key_from_password(pword)
        fernet = Fernet(key)

        for file in files:
            if file not in EXCEPTIONS:
                decide(file, fernet)
    except InvalidToken:
        print("Invalid key!")
    except Exception as ex:
        print("Error: %s" % str(ex))
    finally:
        if is_windows():
            os.system("timeout /t 3 >nul")
