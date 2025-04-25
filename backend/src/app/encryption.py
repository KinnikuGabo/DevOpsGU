from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
from dotenv import load_dotenv

load_dotenv()

class DatabaseEncryptor:
    def __init__(self):
        # Configuración desde variables de entorno
        self.pepper = os.getenv('DB_ENCRYPTION_PEPPER', 'default-pepper-value').encode()
        self.salt = os.getenv('DB_ENCRYPTION_SALT', 'default-salt-value').encode()
        
        # Deriva una clave segura usando PBKDF2
        self.key = PBKDF2(
            self.pepper, 
            self.salt, 
            dkLen=32,  # 256 bits para AES-256
            count=100000  # Iteraciones para hacer más difícil ataques de fuerza bruta
        )
    
    def encrypt_data(self, plaintext: str) -> str:
        """Cifra datos sensibles para almacenamiento en BD"""
        if not plaintext:
            return plaintext
            
        try:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Error en cifrado: {str(e)}")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Descifra datos recuperados de la BD"""
        if not encrypted_data:
            return encrypted_data
            
        try:
            data = base64.b64decode(encrypted_data.encode('utf-8'))
            iv = data[:AES.block_size]
            ciphertext = data[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            return plaintext
        except Exception as e:
            raise ValueError(f"Error en descifrado: {str(e)}")

# Instancia global para uso en la aplicación
db_encryptor = DatabaseEncryptor()