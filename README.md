# **Secure Chat Application**
This project implements a secure, multi-client chat application built with Python. It provides end-to-end encrypted communication, user authentication, and the ability to send both text messages and files in a real-time environment.

## **Table of Contents**
Features

Architecture

Technologies Used

Setup and Installation

Usage

Authentication



## **Features**
Secure Communication:

     Key Exchange: Uses X25519 elliptic curve Diffie-Hellman for secure key exchange, establishing a unique shared symmetric key for each client-server session.

Authenticated Encryption:
      All data (messages and files) are encrypted using AES-256 in GCM mode, ensuring both data confidentiality and integrity.

Key Derivation: 
     HKDF is employed for robust derivation of AES keys from the shared secrets.

Multi-Client Support: 
     The server can handle multiple concurrent client connections, with each client managed in its own dedicated thread.

File Transfer: 
     Clients can send encrypted files to the server, which are saved to a downloads directory.

User Authentication: 
     Clients must log in with a username and password before accessing chat functionalities.

Interactive GUI Client:

     Built with customtkinter for a modern look.

Theme Switching: 
     Toggle between dark (dark blue/green) and light (white/black) themes.

Emoji Support: 
     Text-based emojis with an integrated picker.

Typing Indicator: 
     Real-time "Typing..." status feedback.

Robust Data Transfer: 
     Implements a 4-byte length-prefixing protocol for all data transmissions to ensure complete and reliable receipt of messages and files, preventing disconnections due to partial data.

## **Architecture**
The application follows a Client-Server Architecture:

### Server (server.py):

Listens for incoming client connections.

Manages secure key exchange and user authentication for each client.

Spawns dedicated threads for authenticated clients to handle bidirectional message and file transfer.

### Client (client.py):

Connects to the server and performs key exchange.

Presents a login interface for user authentication.

Activates the chat GUI upon successful login, allowing users to send text messages and files.

## **Cryptographic Utilities (crypto_utils.py):**

A shared module containing all core cryptographic functions, ensuring consistent and centralized security operations.

Technologies Used
Python 3.x

socket: For network communication (TCP/IP).

threading: For concurrent handling of multiple clients and I/O operations.

cryptography library: For robust cryptographic primitives (X25519, AES-GCM, HKDF).

customtkinter: For creating the modern graphical user interface.

struct: For binary data packing/unpacking (length-prefixing).

os, tkinter.filedialog: For file system interactions and file selection.

**Setup and Installation**
To run this application, follow these steps:

Clone the repository (or create the files):
Ensure you have server.py, client.py, and crypto_utils.py in the same directory.

Install Dependencies:
Open your terminal or command prompt and run:

pip install customtkinter cryptography

Usage
Start the Server:
Open a terminal and navigate to the project directory. Run the server script:

python server.py

The server will start listening for connections.

Start the Client:
Open another terminal (or multiple terminals for multiple clients) and navigate to the project directory. Run the client script:

python client.py

The client GUI will appear.

Authentication
When the client application starts, you will be presented with a login screen.

Default Credentials: For demonstration purposes, the hardcoded credentials are:

**Username: esha**

**Password: esha123**

Enter these credentials and click "Login" to access the chat interface.