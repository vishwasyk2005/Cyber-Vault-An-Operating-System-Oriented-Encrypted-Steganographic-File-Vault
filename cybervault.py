import argparse
import getpass
import os

from core.encryptor import encrypt_file, decrypt_file
from core.stego import hide_data_in_image, extract_data_from_image
from os_layer.file_manager import read_binary, write_binary
from os_layer.permissions import secure_file

VAULT_DIR = "vaults"
os.makedirs(VAULT_DIR, exist_ok=True)


def lock_file(secret_file, cover_image):
    password = getpass.getpass("Enter password: ").encode()

    encrypted_data = encrypt_file(secret_file, password)
    vault_path = os.path.join(VAULT_DIR, "vault.png")

    hide_data_in_image(cover_image, encrypted_data, vault_path)
    secure_file(vault_path)
    os.remove(secret_file)

    print(" Vault created and original file securely stored in image", vault_path)



def unlock_file(vault_image):
    password = getpass.getpass("Enter password: ").encode()

    encrypted_data = extract_data_from_image(vault_image)
    output_file = decrypt_file(encrypted_data, password)

    print(" File recovered:", output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberVault OS Utility")

    parser.add_argument("action", choices=["lock", "unlock"])
    parser.add_argument("--file", help="Secret file")
    parser.add_argument("--cover", help="Cover image")
    parser.add_argument("--vault", help="Vault image")

    args = parser.parse_args()

    if args.action == "lock":
        lock_file(args.file, args.cover)

    elif args.action == "unlock":
        unlock_file(args.vault)
