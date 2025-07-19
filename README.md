# 🔐 Encrypted Chat with Diffie-Hellman Key Exchange

This project implements secure communication between two users using:
- Diffie-Hellman for key exchange
- AES for encrypted message exchange

## ✅ Features

- Encrypted messaging using AES-CBC
- Secure key exchange using Diffie-Hellman
- Realtime chat via sockets
- Multi-threaded message sending/receiving

## 📂 Files

- `server.py` — Acts as User B, accepts connections
- `client.py` — Acts as User A, connects to server
- `crypto_utils.py` — Contains key exchange and encryption functions
- `requirements.txt` — Python dependencies

## 🚀 How to Run

```bash
pip install -r requirements.txt

🛠️ Tech Stack
Python

Sockets

Cryptography (Diffie-Hellman, AES, HKDF)