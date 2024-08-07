import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import configparser
import os

CONFIG_FILE = "config.ini"

def decrypt_aes(key, iv, encrypted_text):
    try:
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes")
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")

        key_bytes = key.encode('utf-8')
        iv_bytes = iv.encode('utf-8')
        encrypted_bytes = base64.b64decode(encrypted_text)

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_bytes) + unpadder.finalize()

        return decrypted_data.decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}"

def process_input(event=None):
    key = key_entry.get()
    iv = iv_entry.get()
    encrypted_text = encrypted_text_entry.get("1.0", tk.END).strip()
    save_config(key, iv)

    decrypted_text_output.config(state='normal')
    decrypted_text_output.delete("1.0", tk.END)
    decrypted_text_output.config(state='disabled')

    error_text_output.config(state='normal')
    error_text_output.delete("1.0", tk.END)
    error_text_output.config(state='disabled')

    patterns = encrypted_text.splitlines()

    for pattern in patterns:
        result = decrypt_aes(key, iv, pattern.strip())
        if "Error" in result:
            error_text_output.config(state='normal')
            error_text_output.insert(tk.END, f"Error decrypting {pattern}: {result}\n")
            error_text_output.config(state='disabled')
        else:
            decrypted_text_output.config(state='normal')
            decrypted_text_output.insert(tk.END, f"{result}\n")
            decrypted_text_output.config(state='disabled')

def save_config(key, iv):
    config = configparser.ConfigParser()
    config['DEFAULT'] = {'Key': key, 'IV': iv}
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def load_config():
    if os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        key_entry.insert(0, config['DEFAULT'].get('Key', ''))
        iv_entry.insert(0, config['DEFAULT'].get('IV', ''))

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("AES Decryption Tool")

# Ajustes para hacer la interfaz más amigable
root.geometry("600x450")
root.resizable(True, True)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(3, weight=1)

# Establecer un icono para el software
try:
    if os.name == 'nt':  # Windows
        root.iconbitmap('/Users/adolfopardo/PycharmProjects/AESTool/ico/icono.ico')
    else:  # macOS y otros sistemas
        root.iconphoto(True, tk.PhotoImage(file='/Users/adolfopardo/PycharmProjects/AESTool/ico/ico/icono.png'))
except Exception as e:
    print(f"No se pudo cargar el icono: {e}")

tk.Label(root, text="Key:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

tk.Label(root, text="IV:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
iv_entry = tk.Entry(root, width=50)
iv_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

tk.Label(root, text="Encrypted Text:").grid(row=2, column=0, padx=5, pady=5, sticky='ne')
encrypted_text_entry = scrolledtext.ScrolledText(root, width=50, height=10)
encrypted_text_entry.grid(row=2, column=1, padx=5, pady=5, sticky='nsew')
encrypted_text_entry.bind("<KeyRelease>", process_input)

tk.Label(root, text="Decrypted Output:").grid(row=3, column=0, padx=5, pady=5, sticky='ne')
decrypted_text_output = scrolledtext.ScrolledText(root, width=50, height=10, state='disabled')
decrypted_text_output.grid(row=3, column=1, padx=5, pady=5, sticky='nsew')

tk.Label(root, text="Error Messages:").grid(row=4, column=0, padx=5, pady=5, sticky='ne')
error_text_output = scrolledtext.ScrolledText(root, width=50, height=4, state='disabled', fg='red')
error_text_output.grid(row=4, column=1, padx=5, pady=5, sticky='nsew')

load_config()

root.mainloop()
