import socket
import threading
import sqlite3
import tkinter as tk
import sys
import rsa

HOST = "192.168.0.101"
PORT = 8888

PUBLIC_KEY_SIZE = 2048

# Connect to the database (this will create a new database if it doesn't exist)
conn = sqlite3.connect('chat.db')
cursor = conn.cursor()

# Create a table to store chat messages
cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        sender TEXT,
        message TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Commit changes and close the connection
conn.commit()
conn.close()

def send_message(self, event=None):
    message = self.input_field.get()
    if message.lower() == "quit":
        self.client_socket.send(rsa.encrypt(message.encode('utf-8'), self.public_partner))
        self.client_socket.close()
        self.root.destroy()
    else:
        self.client_socket.send(rsa.encrypt(f"{self.username}: {message}".encode('utf-8'), self.public_partner))
        self.save_message_to_database(self.username, message)  # Save message to the database
        self.input_field.delete(0, tk.END)

def save_message_to_database(self, sender, message):
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (sender, message) VALUES (?, ?)', (sender, message))
    conn.commit()
    conn.close()
def load_messages_from_database(self):
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('SELECT sender, message FROM messages ORDER BY timestamp')
    messages = cursor.fetchall()
    conn.close()
    
    for sender, message in messages:
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, f"{sender}: {message}\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.see(tk.END)

# Call this method when initializing the GUI to load messages from the database

root = tk.Tk()


class ChatServer:
    def __init__(self):
        self.clients = {}
        self.lock = threading.Lock()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((HOST, PORT))
        print(f"Server is starting......\n[LISTENING] on {HOST}:{PORT}")

        self.public_key, self.private_key = rsa.newkeys(PUBLIC_KEY_SIZE)

    def broadcast(self, message, sender_name=None):
        with self.lock:
            for client_name, client_data in self.clients.items():
                if sender_name != client_name:
                    encrypted_message = rsa.encrypt(message.encode('utf-8'), client_data['public_key'])
                    client_data['socket'].send(encrypted_message)

    def handle_client(self, client_socket, client_address):
        try:
            public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))
            client_name = rsa.decrypt(client_socket.recv(1024), self.private_key).decode('utf-8')
            print(f"\n{client_name} [JOINED] chat community :)")
            self.clients[client_name] = {'socket': client_socket, 'public_key': public_key}
            self.broadcast(f"\n{client_name} joined the chat\n", client_name)

            while True:
                encrypted_message = client_socket.recv(1024)

                if not encrypted_message:
                    break

                decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')

                if decrypted_message.lower() == "quit":
                    self.broadcast(f"{client_name} LEFT THE CHAT!", client_name)
                    client_socket.close()
                    with self.lock:
                        del self.clients[client_name]
                    break
                else:
                    self.broadcast(f"{client_name}: {decrypted_message}", client_name)

        except Exception as e:
            print(f"[EXCEPTION] due to {e}")

    def start_server(self):
        try:
            self.server.listen()

            while True:
                client_socket, client_address = self.server.accept()
                print(f"[NEW CONNECTION] from {client_address}!")
                client_socket.send(self.public_key.save_pkcs1("PEM"))
                threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

        except KeyboardInterrupt:
            print("Server is terminating...")
            with self.lock:
                for client_data in self.clients.values():
                    client_data['socket'].close()
            self.server.close()

if __name__ == '__main__':
    chat_server = ChatServer()
    chat_server.start_server()
