import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
_main_key = None

def initialize(config):
    global _main_key
    _main_key = config["password"].encode("utf-8")


def end():
    global _main_key
    _main_key = None


def generate_salt(length=16):
    return os.urandom(length)


def _derive_key(password, salt, iterations=200_000):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        iterations,
        dklen=32
    )


def _pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt(file_path, output_path, salt=None):
    if _main_key is None:
        raise ValueError("Encryption system not initialized")

    if salt is None:
        salt = b""
    elif len(salt) > 255:
        salt = salt[:255]

    key = _derive_key(_main_key, salt)
    iv = os.urandom(BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(_pad(plaintext))

    # New format: [salt_len][salt][iv][ciphertext]
    with open(output_path, "wb") as f:
        f.write(bytes([len(salt)]))
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)


def decrypt(file_path, output_path, salt=None):
    if _main_key is None:
        raise ValueError("Encryption system not initialized")

    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) < BLOCK_SIZE:
        raise ValueError("Invalid encrypted file")

    # Try new format first
    try:
        salt_len = data[0]
        header_len = 1 + salt_len + BLOCK_SIZE

        if header_len > len(data):
            raise ValueError

        ciphertext = data[header_len:]
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError

        file_salt = data[1:1 + salt_len]
        iv = data[1 + salt_len:header_len]

        if salt is None:
            salt = file_salt
        else:
            if len(salt) < salt_len:
                raise ValueError("Provided salt too short")
            salt = salt[:salt_len]

    except ValueError:
        # Legacy format: [iv][ciphertext]
        salt = b""
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]

        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Invalid encrypted file")

    key = _derive_key(_main_key, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = _unpad(cipher.decrypt(ciphertext))

    with open(output_path, "wb") as f:
        f.write(plaintext)
