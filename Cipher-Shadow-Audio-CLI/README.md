# 🎵 Cipher-Shadow-Audio-CLI 🔐

A Python-based **Audio Steganography Command Line Tool** that allows you
to **encrypt a hidden message** and embed it inside a **16-bit WAV audio
file**, and later **extract & decrypt** it using a password.

This CLI tool uses **Fernet encryption**, **PBKDF2-HMAC key
derivation**, and **LSB-based audio steganography**, designed for
terminal users, scripting, and automation.

---

## 🧱 Project Structure

    Cipher-Shadow-Audio-CLI/
    │
    ├── audio_encrypt_cli.py         # Main GUI Application
    └── README.md                    # Project documentation

---

## ✨ Features

### 🔐 Encryption & Embedding

- Encrypts message using **Fernet (AES-128 authenticated encryption)**
- Derives key from password using **PBKDF2-HMAC (SHA256)**
- Embeds encrypted payload into WAV audio using **LSB (Least Significant Bit)**

### 🔓 Extraction & Decryption

- Extracts embedded payload from WAV
- Uses stored salt to regenerate the Fernet key
- Decrypts message securely
- Prints decrypted message directly in terminal

---

## 🛠 Technologies Used

| Technology                             | Role                      |
| -------------------------------------- | ------------------------- |
| **Python 3**                           | Main language             |
| **argparse**                           | CLI argument parsing      |
| **wave module**                        | WAV file operations       |
| **array module**                       | Audio sample manipulation |
| **cryptography (Fernet + PBKDF2HMAC)** | Encryption                |
| **LSB Steganography**                  | Data embedding            |

---

## 📌 Requirements

``` bash
pip install cryptography
```

Standard libraries like `wave`, `array`, `tkinter`, `base64`, and `struct` are already included with Python.

---

## ▶️ How to Run

**1. Clone the repository:**

```bash
git clone https://github.com/ShakalBhau0001/Cipher-Shadow.git
```

**2. Enter the project folder:**

```bash
cd Cipher-Shadow-Audio-CLI
```

**3. Run the GUI:**

```bash
python audio_encrypt_cli.py
```

---

## ▶️ Usage

### 🔐 Encrypt & Embed

#### 1. Text Encrypt & Embed

``` bash
python audio_encrypt_cli.py encrypt --in-wav cover.wav --out-wav stego.wav --password mypass --message "secret"
```

```bash
python audio_encrypt_cli.py encrypt --in-wav inputfile.wav --out-wav outputfile.wav --password yourpassword --message "Enter Your Secret Message"
```

#### 2. Text File Encrypt & Embed

``` bash
python audio_encrypt_cli.py encrypt --in-wav cover.wav --out-wav stego.wav --password mypass --message-file secret.txt
```

```bash
python audio_encrypt_cli.py encrypt --in-wav inputfile.wav --out-wav outputfile.wav --password yourpassword --message-file Add Your Secret txt file
```

### 🔓 Decrypt & Extract

``` bash
python audio_encrypt_cli.py decrypt --in-wav stego.wav --password mypass
```

```bash
python audio_encrypt_cli.py decrypt --in-wav outputfile.wav --password yourpassword
```

---

## 📁 Supported Format

- **Input (Carrier):** 16-bit PCM **WAV** only
- **Output (Stego Audio):** WAV
- **Message Input:** Text or `.txt` file

> ⚠️ If audio is not 16-bit PCM, the app will reject it.

---

## ⚙️ How It Works

**1️⃣ Key Derivation**

- Password → PBKDF2-HMAC(SHA256, 390k iterations) → 32-byte key → Fernet key

**2️⃣ Encryption**

- Message encrypted using Fernet
- Payload format:
  ```bash
  [AUDS][16-byte salt][4-byte length][encrypted data]
  ```

**3️⃣ Embedding**

- Payload bits are inserted into **LSB of audio samples.**

**4️⃣ Extraction**

- Reads LSB bits
- Reconstructs payload
- Validates header
- Re-derives Fernet key
- Decrypts message

---
## ⚠️ Common Errors

- **Wrong password** → Decryption fails
- **Non-16-bit WAV** → Rejected
- **Small audio file** → Payload too large
- **Wrong WAV file** → MAGIC header not found

---
## 🌟 Future Enhancements

- Add support for larger audio files
- Add progress bar during embedding
- Add message file export option
- Improve error handling for corrupted audio
- Add option for binary file hiding (not just text)

---

## 🪪 Author

> **Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
