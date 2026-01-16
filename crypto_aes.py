import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Global key material
_main_key = None

BLOCK_SIZE = 16  # AES block size


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
        dklen=32  # AES-256
    )


def _pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt(file_path, output_path, salt=None):
    if _main_key is None:
        raise ValueError("Encryption system not initialized")

    if salt is None:
        salt = generate_salt()

    key = _derive_key(_main_key, salt)
    iv = get_random_bytes(BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(_pad(plaintext))

    # File format: [salt][iv][ciphertext]
    with open(output_path, "wb") as f:
        f.write(salt + iv + ciphertext)


def decrypt(file_path, output_path, salt=None):
    if _main_key is None:
        raise ValueError("Encryption system not initialized")

    with open(file_path, "rb") as f:
        data = f.read()

    if salt is None:
        salt = data[:16]

    iv = data[16:32]
    ciphertext = data[32:]

    key = _derive_key(_main_key, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = _unpad(cipher.decrypt(ciphertext))

    with open(output_path, "wb") as f:
        f.write(plaintext)
