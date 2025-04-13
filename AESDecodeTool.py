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

def center_window(root, width=700, height=500):
    # Obtener el tamaño de la pantalla
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Calcular la posición x, y para centrar
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)

    root.geometry(f"{width}x{height}+{x}+{y}")

def decrypt_aes(key, iv, encrypted_text):
    """
    Función para desencriptar con AES (CBC + PKCS7).
    """
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


def encrypt_aes(key, iv, plain_text):
    """
    Función para encriptar con AES (CBC + PKCS7).
    """
    try:
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes")
        if len(iv) != 16:
            raise ValueError("IV length must be 16 bytes")

        key_bytes = key.encode('utf-8')
        iv_bytes = iv.encode('utf-8')
        plain_bytes = plain_text.encode('utf-8')

        # Aplicar PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_bytes) + padder.finalize()

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()

        # Retornar en Base64
        encoded_cipher = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encoded_cipher
    except Exception as e:
        return f"Error: {str(e)}"


def process_decryption_input(event=None):
    """
    Procesa el texto cifrado línea a línea y muestra el resultado en la pestaña de DESENCRIPTAR.
    """
    key = decrypt_key_entry.get()
    iv = decrypt_iv_entry.get()
    encrypted_text = decrypt_input_text.get("1.0", tk.END).strip()

    # Guardar la config de desencriptación
    save_decrypt_config(key, iv)

    # Limpiar outputs
    decrypt_output_text.config(state='normal')
    decrypt_output_text.delete("1.0", tk.END)
    decrypt_output_text.config(state='disabled')

    decrypt_error_text.config(state='normal')
    decrypt_error_text.delete("1.0", tk.END)
    decrypt_error_text.config(state='disabled')

    patterns = encrypted_text.splitlines()

    for pattern in patterns:
        result = decrypt_aes(key, iv, pattern.strip())
        if "Error" in result:
            decrypt_error_text.config(state='normal')
            decrypt_error_text.insert(tk.END, f"Error decrypting {pattern}: {result}\n")
            decrypt_error_text.config(state='disabled')
        else:
            decrypt_output_text.config(state='normal')
            decrypt_output_text.insert(tk.END, f"{result}\n")
            decrypt_output_text.config(state='disabled')


def process_encryption_input(event=None):
    """
    Procesa el texto en claro línea a línea y muestra el resultado en la pestaña de ENCRIPTAR.
    """
    key = encrypt_key_entry.get()
    iv = encrypt_iv_entry.get()
    plain_text = encrypt_input_text.get("1.0", tk.END).strip()

    # Guardar la config de encriptación
    save_encrypt_config(key, iv)

    # Limpiar outputs
    encrypt_output_text.config(state='normal')
    encrypt_output_text.delete("1.0", tk.END)
    encrypt_output_text.config(state='disabled')

    encrypt_error_text.config(state='normal')
    encrypt_error_text.delete("1.0", tk.END)
    encrypt_error_text.config(state='disabled')

    lines = plain_text.splitlines()

    for line in lines:
        result = encrypt_aes(key, iv, line.strip())
        if "Error" in result:
            encrypt_error_text.config(state='normal')
            encrypt_error_text.insert(tk.END, f"Error encrypting {line}: {result}\n")
            encrypt_error_text.config(state='disabled')
        else:
            encrypt_output_text.config(state='normal')
            encrypt_output_text.insert(tk.END, f"{result}\n")
            encrypt_output_text.config(state='disabled')


def save_decrypt_config(key, iv):
    """
    Guarda Key e IV para DESENCRIPTAR en la sección [DECRYPT] del config.ini
    """
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)

    if 'DECRYPT' not in config:
        config['DECRYPT'] = {}

    config['DECRYPT']['Key'] = key
    config['DECRYPT']['IV'] = iv

    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def save_encrypt_config(key, iv):
    """
    Guarda Key e IV para ENCRIPTAR en la sección [ENCRYPT] del config.ini
    """
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)

    if 'ENCRYPT' not in config:
        config['ENCRYPT'] = {}

    config['ENCRYPT']['Key'] = key
    config['ENCRYPT']['IV'] = iv

    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def load_config():
    """
    Carga Key e IV guardados en config.ini (secciones [DECRYPT] y [ENCRYPT]).
    """
    if os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)

        if 'DECRYPT' in config:
            decrypt_key = config['DECRYPT'].get('Key', '')
            decrypt_iv = config['DECRYPT'].get('IV', '')
            decrypt_key_entry.insert(0, decrypt_key)
            decrypt_iv_entry.insert(0, decrypt_iv)

        if 'ENCRYPT' in config:
            encrypt_key = config['ENCRYPT'].get('Key', '')
            encrypt_iv = config['ENCRYPT'].get('IV', '')
            encrypt_key_entry.insert(0, encrypt_key)
            encrypt_iv_entry.insert(0, encrypt_iv)


# ---------------------------------------------------------------
#  Configuración de la interfaz gráfica
# ---------------------------------------------------------------
root = tk.Tk()
center_window(root)
root.title("AES Tool - Decrypt & Encrypt")

# Ajustes para el tamaño y la opción de re-dimensionar
root.geometry("700x500")
root.resizable(True, True)

# Establecer un icono para el software (modifica la ruta si lo deseas)
try:
    if os.name == 'nt':  # Windows
        root.iconbitmap('/Users/adolfopardo/PycharmProjects/AESTool/ico/icono.ico')
    else:  # macOS y otros sistemas
        root.iconphoto(True, tk.PhotoImage(file='/Users/macbookairm1/Documents/pythonprojects/AESDecryptTool/ico/icono.png'))
except Exception as e:
    print(f"No se pudo cargar el icono: {e}")

# Crear Notebook (pestañas)
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

# ---------------------------------------------------------------
#  Pestaña de DESENCRIPTAR
# ---------------------------------------------------------------
decrypt_tab = ttk.Frame(notebook)
notebook.add(decrypt_tab, text="Desencriptar")

# Labels y Entries para Key e IV
tk.Label(decrypt_tab, text="Key:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
decrypt_key_entry = tk.Entry(decrypt_tab, width=50)
decrypt_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

tk.Label(decrypt_tab, text="IV:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
decrypt_iv_entry = tk.Entry(decrypt_tab, width=50)
decrypt_iv_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

# Texto a desencriptar
tk.Label(decrypt_tab, text="Encrypted Text:").grid(row=2, column=0, padx=5, pady=5, sticky='ne')
decrypt_input_text = scrolledtext.ScrolledText(decrypt_tab, width=50, height=8)
decrypt_input_text.grid(row=2, column=1, padx=5, pady=5, sticky='nsew')
decrypt_input_text.bind("<KeyRelease>", process_decryption_input)

# Salida del texto desencriptado
tk.Label(decrypt_tab, text="Decrypted Output:").grid(row=3, column=0, padx=5, pady=5, sticky='ne')
decrypt_output_text = scrolledtext.ScrolledText(decrypt_tab, width=50, height=8, state='disabled')
decrypt_output_text.grid(row=3, column=1, padx=5, pady=5, sticky='nsew')

# Salida de errores
tk.Label(decrypt_tab, text="Error Messages:").grid(row=4, column=0, padx=5, pady=5, sticky='ne')
decrypt_error_text = scrolledtext.ScrolledText(decrypt_tab, width=50, height=4, state='disabled', fg='red')
decrypt_error_text.grid(row=4, column=1, padx=5, pady=5, sticky='nsew')

# Ajustar filas y columnas en la pestaña de desencriptar
decrypt_tab.grid_columnconfigure(1, weight=1)
decrypt_tab.grid_rowconfigure(2, weight=1)
decrypt_tab.grid_rowconfigure(3, weight=1)
decrypt_tab.grid_rowconfigure(4, weight=1)

# ---------------------------------------------------------------
#  Pestaña de ENCRIPTAR
# ---------------------------------------------------------------
encrypt_tab = ttk.Frame(notebook)
notebook.add(encrypt_tab, text="Encriptar")

# Labels y Entries para Key e IV
tk.Label(encrypt_tab, text="Key:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
encrypt_key_entry = tk.Entry(encrypt_tab, width=50)
encrypt_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

tk.Label(encrypt_tab, text="IV:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
encrypt_iv_entry = tk.Entry(encrypt_tab, width=50)
encrypt_iv_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

# Texto plano a encriptar
tk.Label(encrypt_tab, text="Plain Text:").grid(row=2, column=0, padx=5, pady=5, sticky='ne')
encrypt_input_text = scrolledtext.ScrolledText(encrypt_tab, width=50, height=8)
encrypt_input_text.grid(row=2, column=1, padx=5, pady=5, sticky='nsew')
encrypt_input_text.bind("<KeyRelease>", process_encryption_input)

# Salida del texto encriptado
tk.Label(encrypt_tab, text="Encrypted Output:").grid(row=3, column=0, padx=5, pady=5, sticky='ne')
encrypt_output_text = scrolledtext.ScrolledText(encrypt_tab, width=50, height=8, state='disabled')
encrypt_output_text.grid(row=3, column=1, padx=5, pady=5, sticky='nsew')

# Salida de errores
tk.Label(encrypt_tab, text="Error Messages:").grid(row=4, column=0, padx=5, pady=5, sticky='ne')
encrypt_error_text = scrolledtext.ScrolledText(encrypt_tab, width=50, height=4, state='disabled', fg='red')
encrypt_error_text.grid(row=4, column=1, padx=5, pady=5, sticky='nsew')

# Ajustar filas y columnas en la pestaña de encriptar
encrypt_tab.grid_columnconfigure(1, weight=1)
encrypt_tab.grid_rowconfigure(2, weight=1)
encrypt_tab.grid_rowconfigure(3, weight=1)
encrypt_tab.grid_rowconfigure(4, weight=1)

# Cargar configuración almacenada
load_config()

# Iniciar el bucle principal de la aplicación
root.mainloop()
