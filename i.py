



import socket
import threading
import rsa
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import hashlib
import sqlite3

HOST = "192.168.0.101"
PORT = 8888

PUBLIC_KEY_SIZE = 2048

class SignInWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Sign In")
        self.root.geometry("300x150")

        self.username_label = tk.Label(root, text="Username:")
        self.username_label.pack()

        self.username_entry = tk.Entry(root)
        self.username_entry.pack()

        self.sign_in_button = tk.Button(root, text="Sign In", command=self.sign_in)
        self.sign_in_button.pack()

    def sign_in(self):
        username = self.username_entry.get()
        if username:
            self.root.destroy()
            client_gui = ClientGUI(username)
        else:
            messagebox.showerror("Error", "Please enter a username.")
class ClientGUI:
    def __init__(self, username):
        self.username = username
    def __init__(self, root):
        self.root = root
        self.root.title("Group secure chat")
        
        # Set background color
        self.root.configure(bg="#075e54")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, bg="#d7ccc8", fg="#000000")
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Set input frame background color
        self.input_frame = tk.Frame(root, bg="#075e54")
        self.input_frame.pack(fill=tk.BOTH, padx=10, pady=10)
        
        self.input_field = tk.Entry(self.input_frame, bg="#ffffff")
        self.input_field.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.input_field.bind("<Return>", self.send_message)
        
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message, bg="#128c7e", fg="#ffffff")
        self.send_button.pack(side=tk.RIGHT)
        
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

        self.public_key, self.private_key = rsa.newkeys(PUBLIC_KEY_SIZE)
        self.client_socket.send(self.public_key.save_pkcs1("PEM"))
        self.public_partner = rsa.PublicKey.load_pkcs1(self.client_socket.recv(1024))
       
        self.username = simpledialog.askstring("Sign in", "Enter your username:")
        self.client_socket.send(rsa.encrypt(self.username.encode('utf-8'), self.public_partner))

        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()


    def send_message(self, event=None):
        message = self.input_field.get()
        if message.lower() == "quit":
            self.client_socket.send(rsa.encrypt(message.encode('utf-8'), self.public_partner))
            self.client_socket.close()
            self.root.destroy()
        else:
            self.client_socket.send(rsa.encrypt(f"{self.username}: {message}".encode('utf-8'), self.public_partner))
            self.input_field.delete(0, tk.END)

    def receive_messages(self):
        try:
            while True:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                else:
                    message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')
                    self.text_area.config(state=tk.NORMAL)
                    self.text_area.insert(tk.END, message + '\n')
                    self.text_area.config(state=tk.DISABLED)
                    self.text_area.see(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Error receiving message: {str(e)}")
        finally:
            self.client_socket.close()
if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("300x150")
    root.resizable(False, False)

    sign_in_window = SignInWindow(root)
    root.mainloop()
if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("600x500")  
    root.resizable(False, False)  
    client_gui = ClientGUI(root)
    root.mainloop()

if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("300x150")
    root.resizable(False, False)

    sign_in_window = SignInWindow(root)
    root.mainloop()

    
