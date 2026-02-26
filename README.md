# 🔐 CyberVault – Secure Steganographic File Vault

CyberVault is a **user-space, OS-oriented secure file vault** that combines **AES-GCM authenticated encryption** with **LSB-based image steganography** to achieve covert and secure data storage.

The system encrypts any file (PDF, TXT, ZIP, Images, etc.) and embeds the encrypted data inside a normal image file. The resulting vault behaves like a standard image while secretly containing protected data.

---

## 📌 Project Overview

* **Domain**: Operating Systems / Cyber Security
* **Focus**: Secure and covert file storage
* **Encryption**: AES-GCM (Authenticated Encryption)
* **Key Derivation**: Scrypt (Password-Based KDF)
* **Steganography**: Least Significant Bit (LSB)
* **Modes**: CLI + GUI

---

## 🚀 Key Features

* 🔐 AES-GCM encryption (confidentiality + integrity)
* 🧂 Secure key derivation using Scrypt with salt
* 🖼 LSB-based steganography
* 📁 Binary-safe file handling (`rb` / `wb`)
* 📦 Chunk-based memory-efficient processing
* 🛡 Tamper detection during decryption
* ⚙ OS-level permission control using `chmod`
* 🖥 Command Line Interface (CLI)
* 🪟 Graphical User Interface (GUI)
* 📂 Supports all file types

---

## 🛠️ Tech Stack

* **Python**
* **cryptography** – AES-GCM & Scrypt
* **Pillow** – Image processing
* **Tkinter** – GUI
* **argparse** – CLI parsing
* **OS module** – File handling & permissions

---

## 📂 Project Structure

```
CyberVault/
├── cybervault.py              # Main CLI controller
├── gui.py                     # Graphical Interface
├── requirements.txt           # Dependencies
├── README.md
├── core/
│   ├── encryptor.py           # AES-GCM encryption/decryption
│   └── stego.py               # LSB embedding & extraction
├── os_layer/
│   ├── file_manager.py        # Chunk-based file handling
│   └── permissions.py         # chmod-based access control
└── vaults/                    # Generated vault images
```

---

## 📥 Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/vishwasyk2005/CyberVault.git
cd CyberVault
```

### 2️⃣ Create Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ How to Run CyberVault

CyberVault supports both **CLI mode** and **GUI mode**.

---

## 🖥 Using Command Line (CLI)

### 🔒 Lock a File

```bash
python cybervault.py lock --file secret.pdf --cover image.png
```

Output:
```
vaults/vault.png
```

---

### 🔓 Unlock a File

```bash
python cybervault.py unlock --vault vaults/vault.png
```

The original file is restored if the password is correct.

If the vault is tampered, decryption fails securely.

---

## 🪟 Using Graphical Interface (GUI)

Launch GUI:

```bash
python gui.py
```

### Lock Workflow
1. Select **Lock**
2. Choose secret file
3. Choose cover image
4. Enter password
5. Click Encrypt
6. Vault image generated successfully

### Unlock Workflow
1. Select **Unlock**
2. Choose vault image
3. Enter password
4. Click Decrypt
5. File is restored

---

## 🛡 Security Model

* AES-GCM provides authenticated encryption.
* Scrypt protects against brute-force attacks.
* Salt ensures unique key derivation.
* Binary file handling prevents encoding corruption.
* `chmod` enforces OS-level access control.
* Tampered encrypted data cannot be decrypted.

---

## 🎯 Operating System Concepts Used

* File system abstraction (byte-stream model)
* Secure binary file I/O
* Chunk-based buffered processing
* Access control using file permissions
* User-space implementation using system calls
* Memory-aware programming

---

## 🧪 Demonstration Capability

CyberVault demonstrates:

* Secure encryption and decryption
* Covert file storage
* Tamper detection (modification causes decryption failure)
* OS-aware programming practices
* Secure password-based key derivation

---

## 📜 License

This project is developed for academic and educational purposes.
