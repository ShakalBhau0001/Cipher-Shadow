## 🔐 Cipher-Shadow  
### A Modular Encryption & Steganography Toolkit (Audio • Image • More)

Cipher-Shadow is a growing Python-based repository focused on **secure encryption and steganography techniques** for multiple digital formats.  
The project currently includes **audio-based encryption & steganography tools** and is designed to expand with **image encryption, image steganography, and additional formats** in the future.

Each module is implemented as an independent sub-project (GUI & CLI), making the repository clean, scalable, and easy to extend.

---

## 📁 Project Structure

```bash

Cipher-Shadow/
│
├── Cipher-Shadow-Audio-GUI/          # GUI-based audio steganography project
│   ├── audio_encrypt_gui.py          # Main Tkinter GUI application
│   └── README.md                     # GUI project documentation
│
├── Cipher-Shadow-Audio-CLI/          # Command-line audio steganography project
│   ├── audio_encrypt_cli.py          # Main CLI application (encrypt/decrypt)
│   └── README.md                     # CLI project documentation
│
└── README.md                         # Main repository overview

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
- Built-in error handling and status updates

**Technology Focus:**
- Tkinter GUI
- Fernet (AES) encryption
- PBKDF2-HMAC key derivation
- LSB audio steganography

📄 See `Cipher-Shadow-Audio-GUI/README.md` for full details.

---

### 2️⃣ Cipher-Shadow-Audio-CLI 🎧💻

A **Command Line Interface (CLI) tool** designed for:
- Terminal users
- Advanced users
- Automation & scripting workflows

It provides the same cryptographic and steganographic capabilities as the GUI version, but controlled entirely via command-line arguments.

**Highlights:**
- Encrypt & embed messages via terminal commands
- Decrypt hidden messages directly in CLI
- Script-friendly and lightweight
- Ideal for security testing and learning purposes

**Technology Focus:**
- argparse for CLI handling
- Fernet encryption
- PBKDF2-HMAC key derivation
- LSB WAV steganography

📄 See `Cipher-Shadow-Audio-CLI/README.md` for usage instructions.

---

## 🔐 Core Concepts Used

- **Fernet Encryption (AES-128, authenticated)**
- **PBKDF2-HMAC (SHA256, 390k iterations)** for key derivation
- **LSB (Least Significant Bit) Steganography**
- **16-bit PCM WAV audio processing**

---

## 📌 Supported Format

- **Carrier Audio:** 16-bit PCM WAV only  
- **Output Audio:** WAV  
- **Hidden Data:** Text / `.txt` file  

> ⚠️ Non–16-bit WAV files are intentionally rejected for safety and correctness.

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
- **wave / array (Audio processing)**
- **cryptography (Fernet + PBKDF2)**
- **LSB Steganography**

---

## 🪪 Author

> **Created by: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
