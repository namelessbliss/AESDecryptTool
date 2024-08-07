from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Clave y vector de inicialización (IV) proporcionados
key = b'Qe3vxOUsYpG7zhBFBY6WeUrg3TC5IyTb'
iv = b'm1tEOdbMTgZx7Qyi'


# Función para desencriptar un valor
def decrypt(encrypted_value, key, iv):
    try:
        # Base64 decode the encrypted value
        encrypted_bytes = base64.b64decode(encrypted_value)

        # Create a cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the value
        decrypted_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()

        # Remove padding (PKCS7)
        pad_len = decrypted_bytes[-1]
        decrypted_bytes = decrypted_bytes[:-pad_len]

        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error decrypting value: {encrypted_value} - {e}")
        return encrypted_value  # Return the encrypted value if decryption fails


# Leer el archivo de texto
input_file_path = 'encrypted_data.txt'
output_file_path = 'decrypted_data_huawei.txt'

with open(input_file_path, 'r') as file:
    lines = file.readlines()

# Procesar cada línea y desencriptar los valores
with open(output_file_path, 'w') as output_file:
    for line in lines:
        if 'to mapOf(' in line or 'Environment.' in line:
            parts = line.split('"')
            for i in range(1, len(parts), 2):
                if parts[i].startswith("fn") or parts[i] == "":
                    continue
                parts[i] = decrypt(parts[i], key, iv)
            output_file.write('"'.join(parts))
        else:
            output_file.write(line)
