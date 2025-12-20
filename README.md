## 🔐 Cipher-Shadow  
### A Modular Encryption & Steganography Toolkit

**Cipher-Shadow** is a growing Python-based repository focused on **secure encryption and steganography techniques** for multiple digital formats.  
The project currently includes :-
- **Audio-based encryption & steganography (GUI + CLI)**
- **Image-based encryption & steganography (GUI + CLI)**

Each module is implemented as an **independent sub-project**, keeping the codebase clean and easy to maintain.

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
├── Cipher-Shadow-File-GUI/             # GUI-based file steganography
│   ├── file_encrypt_gui.py             # Main GUI application
│   └── README.md                       # Project documentation
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

## 🔐 Core Concepts Used

- **Fernet Encryption (AES-128, authenticated)**
- **PBKDF2-HMAC (SHA256, 390,000 iterations)**
- **LSB (Least Significant Bit) Steganography**
- **16-bit PCM WAV audio processing**
- **Binary-safe payload packing**
- **MAGIC header validation**
- **Lossless carrier enforcement**

---

## 📌 Supported Format
- 🎵 Audio :
  - **Carrier Audio:** 16-bit PCM WAV only  
  - **Output Audio:** WAV  
  - **Hidden Data:** Text / `.txt` file

- 🖼️ Image :
  - **Carrier Image:** PNG (recommended), JPG/JPEG
  - **Output Image:** PNG Only  
  - **Hidden Data:** Text / `.txt` file
 

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

3.**Install dependencies (if applicable)**
```bash
pip install -r requirements.txt
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
- **cryptography (Fernet + PBKDF2)**
- **LSB Steganography**

---

## 🪪 Author

> **Created by: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
