## 🔐 Cipher-Shadow  
### A Modular Encryption & Steganography Toolkit

**Cipher-Shadow** is a growing Python-based repository focused on **secure encryption and steganography techniques** for multiple digital formats.  
The project currently includes :-
- **Audio-based encryption & steganography**
- **Image-based encryption & steganography**
- **Generic file encryption & decryption**

Each module is implemented as an **independent sub-project**, keeping the codebase clean and easy to maintain.
Each module works independently, keeping the repository **clean, scalable, and easy to extend**.

---

## 📁 Project Structure

```bash

Cipher-Shadow/
│
├── Cipher-Shadow-Audio-GUI/            # GUI-based audio steganography
│   ├── audio_encrypt_gui.py            # Tkinter GUI application
│   └── README.md                       # Audio GUI documentation
│
├── Cipher-Shadow-Audio-CLI/            # CLI-based audio steganography
│   ├── audio_encrypt_cli.py            # Audio encrypt/decrypt CLI tool
│   └── README.md                       # Audio CLI documentation
│
├── Cipher-Shadow-Image-GUI/            # GUI-based image steganography
│   ├── image_encrypt_gui.py            # Tkinter GUI application
│   └── README.md                       # Image GUI documentation
│
├── Cipher-Shadow-Image-CLI/            # CLI-based image steganography
│   ├── image_encrypt_cli.py            # Image encrypt/decrypt CLI tool
│   └── README.md                       # Image CLI documentation
│
├── Cipher-Shadow-File-GUI/             # GUI-based file encryption/decryption
│   ├── file_encrypt_gui.py             # Tkinter GUI application
│   └── README.md                       # File GUI documentation
│
├── Cipher-Shadow-File-CLI/             # CLI-based file encryption/decryption
│   ├── file_encrypt_cli.py             # File encrypt/decrypt CLI tool
│   └── README.md                       # File CLI documentation
│
└── README.md                           # Main repository overview

```

---

## 🧩 Included Projects

### 1️⃣ Cipher-Shadow-Audio-GUI 🎵🖥️

A **Tkinter-based GUI application** that allows users to:
- Encrypt a secret message using a password
- Embed the encrypted message into a **16-bit PCM WAV file**
- Extract and decrypt the hidden message using the correct password

**Highlights:**
- Clean and user-friendly interface
- Load message from text box or `.txt` file
- Password-based encryption using Fernet
- Real-time status & error handling

**Tech Stack:**
- Tkinter
- Fernet (AES) encryption
- PBKDF2-HMAC key derivation
- LSB audio steganography

📄 See `Cipher-Shadow-Audio-GUI/README.md`

---

### 2️⃣ Cipher-Shadow-Audio-CLI 🎧💻

A **Command Line Interface (CLI) tool** designed for:
- Terminal users
- Automation & scripting
- Security experimentation

**Highlights:**
- Encrypt & embed messages via CLI
- Decrypt messages directly in terminal
- Lightweight and script-friendly
- Ideal for security testing and learning purposes

**Tech Stack:**
- argparse
- Fernet encryption
- PBKDF2-HMAC key derivation
- LSB WAV steganography

📄 See `Cipher-Shadow-Audio-CLI/README.md`

---

### 3️⃣ Cipher-Shadow-Image-GUI 🖼️💻

A **GUI-based image steganography tool** that allows users to:
- Encrypt a secret message using a password
- Embed encrypted data inside images using **LSB steganography**
- Securely extract and decrypt hidden messages

**Highlights:**
- Clean Tkinter GUI
- Supports text or `.txt` file input
- PNG output enforced for data safety
- MAGIC header validation for integrity

**Tech Stack:**
- Tkinter
- Pillow (PIL)
- Fernet (AES) encryption
- PBKDF2-HMAC key derivation
- LSB image steganography

📄 See `Cipher-Shadow-Image-GUI/README.md`

---

### 4️⃣ Cipher-Shadow-Image-CLI 🖼️💻
A **CLI-based image steganography tool** for advanced users and automation.


**Highlights:**
- Script-friendly design
- Uses lossless PNG output
- Payload integrity check using MAGIC header
- Secure password-derived encryption

**Tech Stack:**
- argparse
- Pillow (PIL)
- Fernet (AES-128)
- PBKDF2-HMAC (SHA256)
- LSB Image Steganography

📄 See `Cipher-Shadow-Image-CLI/README.md`

---

#### 5️⃣ Cipher-Shadow-File-GUI 📁🔐
A **GUI-based file encryption & decryption tool** designed to securely protect any file type (documents, images, videos, archives, etc.).

Unlike steganography modules, this project focuses on **pure cryptographic file protection**

**Highlights:**
- Simple, clean Tkinter interface
- Encrypt any file type using a password
- Secure decryption restores the original file name
- Encryption & decryption panels inside a single window

**Tech Stack:**
- Tkinter
- cryptography (Fernet + PBKDF2-HMAC)
- secrets / base64
- Binary-safe file handling

📄 See `Cipher-Shadow-File-GUI/README.md`

---

#### 6️⃣ Cipher-Shadow-File-CLI 📁💻
A **CLI-based file encryption & decryption tool** for users who prefer terminal-based workflows, scripting, and automation.

This module provides the same cryptographic guarantees as the GUI version but is optimized for **headless usage and security testing**.

**Highlights:**
- Encrypt & decrypt any file directly from the terminal
- Password-based encryption using Fernet
- Preserves original file name & content
- Script-friendly and automation-ready
- Clear error handling for invalid files or passwords

**Tech Stack:**
- argparse
- cryptography (Fernet + PBKDF2-HMAC)
- secrets / base64
- Binary-safe file I/O

📄 See `Cipher-Shadow-File-CLI/README.md`

---

## 🔐 Core Concepts Used

- **Fernet Encryption (AES-128, authenticated)**
- **PBKDF2-HMAC (SHA256, 390,000 iterations)**
- **LSB (Least Significant Bit) Steganography**
- **16-bit PCM WAV audio processing**
- **Binary-safe payload packing**
- **MAGIC header validation**
- **Lossless carrier enforcement**
- **Password-based file encryption (non-steganographic)**

---

## 📌 Supported Format
- 🎵 Audio :
  - **Carrier Audio:** 16-bit PCM WAV only  
  - **Output Audio:** WAV  
  - **Hidden Data:** Text / `.txt` file
  - **Interfaces:** GUI & CLI supported

- 🖼️ Image :
  - **Carrier Image:** PNG (recommended), JPG/JPEG
  - **Output Image:** PNG Only  
  - **Hidden Data:** Text / `.txt` file
  - **Interfaces:** GUI & CLI supported

- 📁 File :
  - **Input:** Any file type
  - **Encrypted Output:** `.enc`
  - **Decrypted Output:** Original file (name + bytes preserved)
  - **Interfaces:** GUI & CLI supported

> ⚠️ Lossy formats are avoided for output to prevent data & payload corruption.

---

## 🚀 Getting Started

1. **Clone the repository**
```bash
git clone https://github.com/ShakalBhau0001/Cipher-Shadow.git
```

2. **Navigate to a project folder**
```bash
cd Cipher-Shadow/Cipher-Shadow-Audio-GUI
```

3.**Install dependencies**
```bash
pip install cryptography pillow
```

4. **Run the project**
```bash
python audio_encrypt_gui.py
```

---

## 🧰 Technologies Used

- **Python 3.9+**
- **Tkinter (GUI)**
- **argparse (CLI)**
- **Pillow (Image processing)**
- **wave / array (Audio processing)**
- **cryptography (Fernet + PBKDF2-HMAC)**
- **LSB Steganography**

---

## ⚠️ Security Disclaimer

This project is intended for **educational and learning purposes**.  
While modern cryptographic primitives are used, it has not undergone formal security audits.

---

## 🪪 Author

> **Created by: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
