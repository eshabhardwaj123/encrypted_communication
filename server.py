import socket
import threading
import os
import struct # Added for packing/unpacking message lengths
from crypto_utils import generate_keys, derive_shared_key, aes_encrypt, aes_decrypt
from cryptography.hazmat.primitives import serialization

# Server configuration
HOST = '127.0.0.1'
PORT = 65432

# Initialize the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f"[SERVER] Listening on {HOST}:{PORT}")

# Lists to keep track of connected clients and their shared keys
clients = []  # Stores connected client socket objects
keys = {}     # Maps client socket objects to their derived shared AES keys

# Ensure the 'downloads' directory exists for incoming files
if not os.path.exists("downloads"):
    os.mkdir("downloads")
    print("[SERVER] Created 'downloads' directory.")

def handle_client(conn, addr):
    """
    Handles a single client connection. This function performs key exchange,
    authentication, and then manages both receiving and sending messages/files
    for this client.
    """
    print(f"[SERVER] Connected with {addr}")

    # --- Key Exchange Phase ---
    try:
        # Generate server's ephemeral (temporary) key pair for this specific client session
        server_private_key, server_public_key = generate_keys()

        # 1. Receive client's public key (PEM format)
        client_pub_key_pem = conn.recv(1024)
        if not client_pub_key_pem:
            raise Exception("Client did not send public key during handshake.")

        # Load the client's public key from PEM format
        client_public_key = serialization.load_pem_public_key(client_pub_key_pem)

        # 2. Send server's public key (PEM format) to the client
        conn.send(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # 3. Derive the shared symmetric AES key using Diffie-Hellman (or similar)
        # This key will be used for all subsequent encryption/decryption with this client
        shared_key = derive_shared_key(server_private_key, client_public_key)
        keys[conn] = shared_key # Store the shared key mapped to this client's connection
        print(f"[SERVER] Secure channel established with {addr}.")

    except Exception as e:
        print(f"[SERVER ERROR] Key exchange failed with {addr}: {e}")
        conn.close()
        # Remove the connection from the clients list if it was added before the error
        if conn in clients:
            clients.remove(conn)
        return # Exit the handler if key exchange fails

    # --- Authentication Phase ---
    authenticated = False
    try:
        # The first message after key exchange is expected to be the authentication request
        raw_length = conn.recv(4)
        if not raw_length:
            raise Exception("Client disconnected during authentication handshake.")

        total_expected_bytes = struct.unpack('!I', raw_length)[0]
        full_data = b""
        received_bytes = 0
        while received_bytes < total_expected_bytes:
            chunk = conn.recv(min(total_expected_bytes - received_bytes, 4096))
            if not chunk:
                raise Exception("Incomplete data received during authentication.")
            full_data += chunk
            received_bytes += len(chunk)

        decrypted_auth_data = aes_decrypt(shared_key, full_data)

        if decrypted_auth_data.startswith(b'AUTH'):
            auth_payload = decrypted_auth_data[4:] # Remove 'AUTH' prefix
            username_bytes, password_bytes = auth_payload.split(b'||', 1)
            username = username_bytes.decode('utf-8')
            password = password_bytes.decode('utf-8')

            # --- Simple Hardcoded Authentication Logic ---
            # In a real application, you would check a database or a secure user store
            if username == "esha" and password == "esha123":
                response = b'AUTH_SUCCESS'
                authenticated = True
                print(f"[SERVER] Client {addr} authenticated successfully as {username}.")
            else:
                response = b'AUTH_FAILURE'
                print(f"[SERVER] Client {addr} authentication failed for user: {username}.")

            # Send authentication response back to client
            encrypted_response = aes_encrypt(shared_key, response)
            response_length = len(encrypted_response)
            conn.send(struct.pack('!I', response_length))
            conn.sendall(encrypted_response)

        else:
            # Unexpected message type during authentication phase
            response = b'AUTH_FAILURE_UNEXPECTED_MSG' # Custom failure message
            encrypted_response = aes_encrypt(shared_key, response)
            response_length = len(encrypted_response)
            conn.send(struct.pack('!I', response_length))
            conn.sendall(encrypted_response)
            print(f"[SERVER ERROR] Unexpected message from {addr} during authentication: {decrypted_auth_data.decode(errors='ignore')}")

    except Exception as e:
        print(f"[SERVER ERROR] Authentication process failed with {addr}: {e}")
        authenticated = False # Ensure authenticated is False on error

    # If authentication failed, close connection and exit handler
    if not authenticated:
        conn.close()
        if conn in clients: clients.remove(conn)
        if conn in keys: del keys[conn]
        print(f"[SERVER] Disconnected {addr} due to authentication failure.")
        return

    # --- Communication Threads for this Client (only start if authenticated) ---

    def receive_messages_client():
        """
        Thread function to continuously receive and process data from the client.
        It first reads a 4-byte length prefix, then reads the exact number of bytes.
        Handles both encrypted text messages and encrypted file transfers.
        """
        nonlocal conn, addr, shared_key # Access variables from the outer handle_client scope
        while True:
            try:
                # First, receive the 4-byte length prefix
                raw_length = conn.recv(4)
                if not raw_length: # Client disconnected or sent empty data
                    print(f"[SERVER] Client {addr} disconnected.")
                    break # Exit loop if client disconnects

                # Unpack the length from bytes to an integer
                total_expected_bytes = struct.unpack('!I', raw_length)[0]

                received_bytes = 0
                chunks = []
                while received_bytes < total_expected_bytes:
                    # Calculate how many bytes are still needed
                    bytes_to_read = total_expected_bytes - received_bytes
                    # Receive up to the remaining bytes, or the buffer size (4096)
                    chunk = conn.recv(min(bytes_to_read, 4096))
                    if not chunk: # Connection closed unexpectedly mid-message
                        print(f"[SERVER ERROR] Connection closed unexpectedly while receiving data from {addr}.")
                        break
                    chunks.append(chunk)
                    received_bytes += len(chunk)

                if received_bytes < total_expected_bytes:
                    # This means the connection broke before all data was received
                    raise Exception(f"Incomplete data received from {addr}.")

                full_data = b"".join(chunks)

                # Decrypt the received full data
                decrypted_content = aes_decrypt(shared_key, full_data)

                # Check for the 'FILE' prefix in the decrypted content
                if decrypted_content.startswith(b'FILE'):
                    # It's a file transfer
                    # Remove the 'FILE' prefix before splitting
                    file_payload = decrypted_content[4:]
                    filename_bytes, file_content_bytes = file_payload.split(b'||', 1)
                    filename = filename_bytes.decode('utf-8') # Decode filename from bytes

                    # Save the received file to the 'downloads' directory
                    file_path = os.path.join("downloads", filename)
                    with open(file_path, "wb") as f:
                        f.write(file_content_bytes)
                    print(f"\n[SERVER] File received from {addr} and saved: {filename}")
                else:
                    # It's a regular encrypted message
                    print(f"\n[CLIENT {addr}]: {decrypted_content.decode('utf-8')}")

            except Exception as e:
                print(f"[SERVER ERROR] Receiving from {addr}: {e}")
                break # Exit loop on error or disconnection

    def send_messages_client():
        """
        Thread function to allow the server to send messages to this specific client.
        Messages are taken from server console input and then encrypted.
        Messages are sent with a 4-byte length prefix.
        """
        nonlocal conn, addr, shared_key # Access variables from the outer handle_client scope
        while True:
            try:
                # Prompt the server user for input for this specific client
                msg = input(f"[YOU to {addr}]: ")
                # Encrypt the message before sending
                encrypted_msg = aes_encrypt(shared_key, msg.encode('utf-8'))
                message_length = len(encrypted_msg)
                # Prepend the message length as a 4-byte unsigned integer
                conn.send(struct.pack('!I', message_length))
                # Send the encrypted message data
                conn.sendall(encrypted_msg) # Use sendall to ensure all bytes are sent
            except Exception as e:
                print(f"[SERVER ERROR] Sending to {addr}: {e}")
                break # Exit loop on error or disconnection

    # Start the receive and send threads for this client
    # Daemon threads will terminate automatically when the main program exits
    recv_thread = threading.Thread(target=receive_messages_client, daemon=True)
    recv_thread.start()

    send_thread = threading.Thread(target=send_messages_client, daemon=True)
    send_thread.start()

    # Keep the handle_client thread alive as long as its communication threads are running.
    # This prevents the client's connection from being closed prematurely.
    # A more sophisticated approach might use threading.Event for signaling.
    while recv_thread.is_alive() and send_thread.is_alive():
        import time
        time.sleep(1) # Sleep to prevent busy-waiting

    # --- Client Disconnection Cleanup ---
    print(f"[SERVER] Disconnecting {addr}")
    conn.close() # Close the socket connection
    if conn in clients:
        clients.remove(conn) # Remove from the active clients list
    if conn in keys:
        del keys[conn] # Remove the shared key for this client

def receive_new_connections():
    """
    Main thread function to continuously accept new client connections.
    For each new connection, it starts a new thread to handle that client.
    """
    while True:
        try:
            conn, addr = server.accept()
            clients.append(conn) # Add the new connection to our list
            # Start a new thread to handle this client
            client_handler_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_handler_thread.start()
        except Exception as e:
            print(f"[SERVER ERROR] Accepting new connection: {e}")
            break # Exit loop if there's an error accepting connections

# Start the thread that continuously accepts new client connections
accept_connections_thread = threading.Thread(target=receive_new_connections, daemon=True)
accept_connections_thread.start()

# Keep the main thread alive indefinitely so that the daemon threads (client handlers)
# continue to run in the background. The server will only shut down if explicitly
# interrupted (e.g., Ctrl+C) or if an unhandled error occurs in the main thread.
try:
    while True:
        import time
        time.sleep(1) # Small sleep to prevent high CPU usage
except KeyboardInterrupt:
    print("\n[SERVER] Shutting down...")
    server.close() # Close the main server socket
    # Attempt to close all active client connections gracefully
    for client_conn in list(clients): # Iterate over a copy to avoid modification issues
        try:
            client_conn.close()
            print(f"[SERVER] Closed connection to {client_conn.getpeername()}")
        except socket.error as se:
            print(f"[SERVER] Error closing client connection: {se}")
        except Exception as e:
            print(f"[SERVER] Unexpected error during client shutdown: {e}")
