## 🔐 Cipher-Shadow-File-CLI

A Python-based **File Encryption & Decryption Command Line Tool** that allows users to **securely encrypt any file** using a password and later **decrypt it back to its original form** via terminal commands.

This project uses **Fernet symmetric encryption** with **PBKDF2-HMAC key derivation**, designed for **automation**, **scripting**, **and security learning purposes.**

---

## 🧱 Project Structure

```bash
Cipher-Shadow-File-CLI/
│
├── file_encrypt_cli.py     # Main CLI application
└── README.md               # Project documentation

```

---

## ✨ Features

## 🔐 File Encryption

- Encrypts **any file type** (video, image, audio, documents, binaries,etc.)
- Uses **Fernet (AES-128 authenticated encryption)**
- Password-based key derivation using **PBKDF2-HMAC (SHA256, 390,000 iterations)**
- Generates a secure encrypted file with `.enc` extension
- Stores metadata safely using a **MAGIC header**

## 🔓 File Decryption

- Decrypts `.enc` encrypted files back to original format
- Restores the **original file name and content**
- Detects invalid or corrupted encrypted files
- Protects against wrong password usage

## 🖥 CLI Highlights

- Clean and simple **argparse-based CLI**
- Separate commands for **Encryption and Decryption**
- Supports custom output paths
- Password-protected operations
- Script-friendly & automation-ready
- Works on **all platforms** (Windows / Linux / macOS)
- **Supports all file formats**

---

## 🛠 Technologies Used

| Technology                             | Role                        |
| -------------------------------------- | --------------------------- |
| **Python 3**                           | Core language               |
| **argparse**                           | Command-line parsing        |
| **cryptography (Fernet + PBKDF2HMAC)** | Encryption & key derivation |
| **secrets**                            | Secure salt generation      |
| **base64 / os**                        | Binary & file handling      |

---
## 📌 Requirements

Make sure you install required dependencies:

```bash
pip install cryptography 
```

Standard libraries like  `secrets`, `argparse`, `base64`, and `os` are already included with Python.

---

## ▶️ How to Run

**1. Clone the repository:**

```bash
git clone https://github.com/ShakalBhau0001/Cipher-Shadow.git
```

**2. Enter the project folder:**

```bash
cd Cipher-Shadow-File-CLI
```

**3. Run the GUI:**

```bash
python file_encrypt_cli.py
```

---

## ▶️ Usage

### 🔐 Encrypt a File

``` bash
python file_encrypt_cli.py encrypt --input secret.pdf --password myStrongPass
```

```bash
python file_encrypt_cli.py encrypt --input secret.pdf --password myStrongPass --output secret.enc
```

### 🔓 Decrypt a File

``` bash
python file_encrypt_cli.py decrypt --input secret.pdf.enc --password myStrongPass
```

```bash
python file_encrypt_cli.py decrypt --input secret.pdf.enc --password myStrongPass --output ./output_folder
```

---

## 📁 Supported File Format

- **Input:** Any file type
- **Encrypted Output:** `.enc`
- **Decrypted Output:** Original file format restored

> ⚠️ Encrypted files without a valid MAGIC header will be rejected.

---

## ⚙️ How It Works

**1️⃣ Key Derivation**

- Password → PBKDF2-HMAC(SHA256, 390,000 iterations) → 32-byte key → Fernet key

**2️⃣ Encryption**

- File data encrypted using Fernet
- Encrypted file structure:
    ```bash
    [FILE][16-byte salt][filename length][original filename][encrypted data]
    ```

**3️⃣ Decryption**

- Validates MAGIC header
- Extracts salt & filename
- Re-derives encryption key
- Decrypts file back to original format

---

## ⚠️ Common Errors

- **Wrong password** → Decryption fails
- **Invalid file** → MAGIC header missing
- **Corrupted file** → Decryption error
- **Renamed `.enc` file** → Still works (metadata stored internally)

---

## 🌟 Future Enhancements

- File integrity hash verification
- Folder encryption support
- Progress indicator for large files
- Cross-platform executable build

---

## 🪪 Author

> **Created by: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
