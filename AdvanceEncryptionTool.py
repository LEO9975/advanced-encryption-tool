import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool")
        self.algorithm = tk.StringVar(value="AES-256")
        self.create_widgets()

    def create_widgets(self):
        # Layout setup
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        # Algorithm selection
        ttk.Label(frm, text="Select Algorithm:").grid(row=0, column=0, sticky="w")
        algo_menu = ttk.Combobox(frm, textvariable=self.algorithm, values=["AES-256", "ChaCha20"])
        algo_menu.grid(row=0, column=1, sticky="ew")

        # Password input
        ttk.Label(frm, text="Password:").grid(row=1, column=0, sticky="w")
        self.password_entry = ttk.Entry(frm, show="*")
        self.password_entry.grid(row=1, column=1, sticky="ew")

        # Buttons for encrypt and decrypt
        ttk.Button(frm, text="Encrypt File", command=self.encrypt_file).grid(row=2, column=0, pady=10)
        ttk.Button(frm, text="Decrypt File", command=self.decrypt_file).grid(row=2, column=1, pady=10)

        frm.columnconfigure(1, weight=1)

    def derive_key(self, password, salt, length):
        # Derive a key using PBKDF2 with SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self):
        # Select file to encrypt
        path = filedialog.askopenfilename()
        if not path:
            return

        password = self.password_entry.get()
        algo = self.algorithm.get()

        # Read file content
        with open(path, 'rb') as f:
            data = f.read()

        # Generate random salt and IV
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)

        # Key derivation and encryption
        if algo == "AES-256":
            key = self.derive_key(password, salt, 32)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        elif algo == "ChaCha20":
            key = self.derive_key(password, salt, 32)
            cipher = Cipher(algorithms.ChaCha20(key, iv[:12]), mode=None, backend=default_backend())
            padded_data = data  # No padding needed for ChaCha20
        else:
            messagebox.showerror("Error", "Unsupported algorithm")
            return

        # Encrypt data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Save encrypted file
        out_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if not out_path:
            return

        with open(out_path, 'wb') as f:
            f.write(salt + iv + ciphertext)

        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        # Select file to decrypt
        path = filedialog.askopenfilename()
        if not path:
            return

        password = self.password_entry.get()
        algo = self.algorithm.get()

        # Read encrypted data
        with open(path, 'rb') as f:
            file_data = f.read()

        # Extract salt, IV, and ciphertext
        salt, iv, ciphertext = file_data[:16], file_data[16:32], file_data[32:]

        # Key derivation and decryption
        if algo == "AES-256":
            key = self.derive_key(password, salt, 32)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        elif algo == "ChaCha20":
            key = self.derive_key(password, salt, 32)
            cipher = Cipher(algorithms.ChaCha20(key, iv[:12]), mode=None, backend=default_backend())
        else:
            messagebox.showerror("Error", "Unsupported algorithm")
            return

        # Decrypt data
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding for AES
        if algo == "AES-256":
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
        else:
            data = padded_data

        # Save decrypted file
        out_path = filedialog.asksaveasfilename()
        if not out_path:
            return

        with open(out_path, 'wb') as f:
            f.write(data)

        messagebox.showinfo("Success", "File decrypted successfully!")

# Run the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
