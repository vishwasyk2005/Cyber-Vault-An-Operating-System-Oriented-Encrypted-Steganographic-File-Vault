import os
import struct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password)


def encrypt_file(filepath, password):
    filename = os.path.basename(filepath).encode()

    with open(filepath, "rb") as f:
        file_data = f.read()

    # ── FILE FORMAT ──
    # [4 bytes filename length][filename][file bytes]
    packed_data = (
        struct.pack("I", len(filename)) +
        filename +
        file_data
    )

    salt = os.urandom(16)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)

    encrypted = aes.encrypt(nonce, packed_data, None)

    return salt + nonce + encrypted


def decrypt_file(encrypted_data, password):
    encrypted_data = bytes(encrypted_data)

    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]

    key = derive_key(password, salt)
    aes = AESGCM(key)

    decrypted = aes.decrypt(nonce, ciphertext, None)

    # ── UNPACK METADATA ──
    name_len = struct.unpack("I", decrypted[:4])[0]
    filename = decrypted[4:4 + name_len].decode()
    file_data = decrypted[4 + name_len:]

    with open(filename, "wb") as f:
        f.write(file_data)

    return filename

