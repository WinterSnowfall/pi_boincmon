#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 1.10
@date: 01/02/2021
'''

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class password_helper:
    ALGORITHM = hashes.SHA512
    ITERATIONS = 100000
    LENGTH = 32
    SALT_LENGTH = 16
    
    def __init__(self):
        self.backend = default_backend()
    
    def encrypt_password(self, master_password, password_to_store):
        salt = os.urandom(self.SALT_LENGTH)
        
        master_password_bytes = master_password.encode()
        kdf = PBKDF2HMAC(self.ALGORITHM, self.LENGTH, salt, self.ITERATIONS, self.backend)
        key = base64.urlsafe_b64encode(kdf.derive(master_password_bytes))
        
        encryption_function = Fernet(key)
        encrypted_password = salt + encryption_function.encrypt(password_to_store.encode())
        encrypted_password_base64 = base64.urlsafe_b64encode(encrypted_password).decode()
        
        return encrypted_password_base64
    
    def decrypt_password(self, master_password, encrypted_string_base64):
        encrypted_string = base64.urlsafe_b64decode(encrypted_string_base64.encode())
        salt = encrypted_string[:self.SALT_LENGTH]
        encrypted_password = encrypted_string[self.SALT_LENGTH:]
        
        master_password_bytes = master_password.encode()
        kdf = PBKDF2HMAC(self.ALGORITHM, self.LENGTH, salt, self.ITERATIONS, self.backend)
        key = base64.urlsafe_b64encode(kdf.derive(master_password_bytes))
        
        decryption_function = Fernet(key)
        decrypted_password = decryption_function.decrypt(encrypted_password).decode()
        
        return decrypted_password

if __name__ == "__main__":
    password_to_encypt = input('Please enter the password you want to be encrypted: ')
    master_password = input('Please enter the master encryption/decryption password: ')
    
    password_helper_instance = password_helper()
    encrypted_password = password_helper_instance.encrypt_password(master_password, password_to_encypt)
    print(f'Encrypted text is: {encrypted_password}')
    #decoded_password = password_helper_instance.decrypt_password(master_password, encrypted_password)
    #print(f'Sanity check - decoded password is: {decoded_password}')
