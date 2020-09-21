import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt = 'C\x1b"\xcam\xf9\x87m\xfb\xbds4\x1d)\xde\xaf'
salt = salt.encode()

def encrypt():
      password = input("Please enter a password: ").encode() # This is input in the form of string
      
      kdf = PBKDF2HMAC(
	      algorithm=hashes.SHA256(),
	      length=32,
	      salt=salt,
	      iterations=100000,
	      backend=default_backend()
      )

      key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
      key = key.decode()
      f = Fernet(key)

      token = f.encrypt(input('Please enter your message to encrypt here: ').encode())
      token = token.decode()
      
      print('Key:', key)
      print('Encrypted message:', token)
      
      
def decrypt():
      f = Fernet(input('Please enter the key here: '))
      token = input('Please enter Encrypted Message here: ').encode()

      output = f.decrypt(token)
      message = output.decode()
      print(message)
      
def key_gen():
      password = input("Please enter a password: ").encode() # This is input in the form of string
      
      kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
            )

      key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
      key = key.decode()
      f = Fernet(key)

      print('Key:', key)
      
def salt_gen():
      salt = os.urandom(16)
      print(salt)

try:
      choice = input('(E)-Encrypt ★ (D)-Decrypt ★ (K)-Keygen ★ (S)-Salt ')
      choice = choice.upper()
      if choice == 'E' : encrypt()
      elif choice == 'D' : decrypt()
      elif choice == 'K' : key_gen()
      elif choice == 'S' : salt_gen()
      else: 
            print('You have to choose either "E" or "D"')
      
except:
      print('How can you possibly fuck this up?')
      exit()
