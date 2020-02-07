import unittest
from tpass import initialize_db

# Test Types
#	self.assertTrue(var1)
# 	self.assertFalse(var1)
#	self.assertEqual(var1, var2)
'''

class TestTPass(unittest.TestCase):

    def test_intialization(self):
    	self.assertTrue(initialize_db())

if __name__ == '__main__':
    unittest.main()



import os,base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_keys():
	password = input("Password: ").encode()
	
	aes_key = os.urandom(32)
	print("AES_KEY: {}".format(base64.urlsafe_b64encode(aes_key)))
	salt = os.urandom(16)
	
	kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=100000,
			backend=default_backend()
		)
	hashed_pass = kdf.derive(password)

	#store iv as plaintext
	iv = os.urandom(16)

	#encrypt aes_key which is used to decrypt file
	cipher = Cipher(algorithms.AES(hashed_pass), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encypted_aes_key = encryptor.update(aes_key) + encryptor.finalize()
	print("len(salt): {}\nlen(enc_aes): {}\nlen(iv): {}".format(
		len(salt), len(encypted_aes_key), len(iv)))
	return salt + encypted_aes_key + iv


def decryption(salt, enc_key, iv):
	password = input("Password: ").encode()
	kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=100000,
			backend=default_backend()
		)
	hashed_pass = kdf.derive(password)


	cipher = Cipher(algorithms.AES(hashed_pass), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	return decryptor.update(enc_key) + decryptor.finalize()


file_header = create_keys()

salt = file_header[:16]
enc_key = file_header[16:48]
iv = file_header[48:]

aes_key = decryption(salt, enc_key, iv)
print(base64.urlsafe_b64encode(aes_key))


'''

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

import os,json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()


pt = {}
pt = json.dumps(pt)


pt = pad(pt).encode()

#ct = encryptor.update(pt) + encryptor.finalize()
ct = encryptor.update(pt) + encryptor.finalize()
#ct = encryptor.update(b"a secret message") + encryptor.finalize()

decryptor = cipher.decryptor()
print(unpad(decryptor.update(ct) + decryptor.finalize()).decode())


















