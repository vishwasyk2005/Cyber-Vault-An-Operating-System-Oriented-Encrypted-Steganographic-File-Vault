🔐 CyberVault

CyberVault is a user-space, OS-oriented secure file vault that encrypts files using AES-GCM authenticated encryption and hides the encrypted data inside image files using LSB-based steganography.

The resulting vault file appears as a normal image to the operating system while secretly containing protected data.

CyberVault demonstrates the practical application of core operating system concepts such as file system abstraction, secure file I/O, memory-efficient processing, and access control.

📌 Features

🔐 AES-GCM authenticated encryption (confidentiality + integrity)

🧂 Secure key derivation using Scrypt with salt

🖼 LSB-based image steganography

📁 Binary-safe file handling (rb / wb)

⚙ Uses standard OS system calls (open, read, write, chmod)

📦 Chunk-based memory-efficient processing

🛡 Tamper detection during decryption

📂 Supports all file types (TXT, PDF, ZIP, Images, etc.)

🖥 CLI and GUI support

🧠 How It Works
🔒 Lock Process

Secret file is opened in binary mode.

A cryptographic key is derived from the password using Scrypt.

The file is encrypted using AES-GCM.

Encrypted bytes are embedded into a cover image using LSB steganography.

A vault image is generated that appears visually unchanged.

🔓 Unlock Process

Encrypted data is extracted from the vault image.

The password regenerates the encryption key.

AES-GCM verifies the authentication tag.

If integrity is valid, the original file is restored.

If the encrypted data is modified, decryption fails securely.

🏗 Project Structure
CyberVault/
├── cybervault.py
├── gui.py
├── README.md
├── requirements.txt
├── core/
│   ├── encryptor.py
│   └── stego.py
├── os_layer/
│   ├── file_manager.py
│   └── permissions.py
└── vaults/
💻 Requirements

Python 3.9+

cryptography

pillow

Install dependencies:

pip install -r requirements.txt
🚀 Installation

Clone the repository:

git clone https://github.com/vishwasyk2005/CyberVault.git
cd CyberVault

Create a virtual environment (recommended):

Linux / Mac:

python -m venv venv
source venv/bin/activate

Windows:

python -m venv venv
venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt
▶ Running CyberVault

CyberVault can be used in two modes:

🖥 Command Line Interface (CLI)

🪟 Graphical User Interface (GUI)

🖥 Using Command Line (CLI)
🔒 Lock a File
python cybervault.py lock --file secret.txt --cover image.png

Output:

vaults/vault.png
🔓 Unlock a File
python cybervault.py unlock --vault vaults/vault.png

The original file will be restored in the current directory.

🪟 Using Graphical User Interface (GUI)

Launch GUI:

python gui.py
Lock Mode

Select Lock

Choose secret file

Choose cover image

Enter password

Click Encrypt & Hide

Vault image is generated successfully

Unlock Mode

Select Unlock

Choose vault image

Enter password

Click Decrypt

Original file is restored

🛡 Security Model

AES-GCM provides authenticated encryption.

Scrypt protects against brute-force attacks.

Salt ensures unique key derivation.

Binary file handling prevents encoding corruption.

chmod enforces OS-level access control.

Tampered encrypted data cannot be decrypted.

🎯 Operating System Concepts Used

File system abstraction (byte-stream model)

Secure file I/O using binary mode

Chunk-based buffered processing

Access control using file permissions

User-space implementation using system calls

Memory-aware programming

🧪 Demonstration Capability

CyberVault can demonstrate:

Secure encryption and decryption

Covert file storage

Tamper detection (modify encrypted data → decryption fails)

OS-aware programming practices

Secure password-based key derivation

📊 Outcomes

Secure file protection achieved

Covert encrypted storage implemented

Memory-efficient OS-aware file processing demonstrated

Integrity-protected decryption ensured

Format-independent file support enabled

📜 License

This project is developed for academic and educational purposes.
