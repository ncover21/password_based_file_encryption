#!/usr/bin/python

import base64, json
import os, getpass, logging
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

logging.basicConfig(level=logging.DEBUG)

SALT_LENGTH = 32
N_ITERATIONS = 1000000
F_CHECK = "pbfe1".encode() #Len: 5
BLOCK_SIZE = 128

def create_keys(hashed_pass, salt):
	aes_key = os.urandom(32)
	iv = os.urandom(16)

	#encrypt aes_key which is used to decrypt file
	cipher = Cipher(algorithms.AES(hashed_pass[:32]), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encypted_aes_key = encryptor.update(aes_key) + encryptor.finalize()
	return (aes_key, salt + hashed_pass[32:] + encypted_aes_key + iv)


def decrypt_aes_key(hash_check, salt, enc_key, iv):
	password = getpass.getpass('Enter password:').encode()
	kdf1 = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=64,
			salt=salt,
			iterations=N_ITERATIONS,
			backend=default_backend()
		)
	hashed_pass = kdf1.derive(password)
	kdf2 = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=64,
			salt=salt,
			iterations=N_ITERATIONS,
			backend=default_backend()
		)
	if( hashed_pass[32:] != hash_check):
		print("Incorrect Password...")
		return decrypt_aes_key(hash_check, salt, enc_key, iv)

	cipher = Cipher(algorithms.AES(hashed_pass[:32]), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	return decryptor.update(enc_key) + decryptor.finalize()

def setup():
	password = getpass.getpass('Enter a password:').encode()

	#Non-Hashed Based Password Verifier
	password_check = getpass.getpass('Re-Enter password:').encode()
	if(password != password_check):
		print("Passwords don't match, try again")
		return setup()

	salt = os.urandom(SALT_LENGTH)
	kdf1 = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=64,
			salt=salt,
			iterations=N_ITERATIONS,
			backend=default_backend()
		)
	key_orig = kdf1.derive(password)
	'''
	#Hash Based Password Verifier
	kdf2 = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=64,
			salt=salt,
			iterations=N_ITERATIONS,
			backend=default_backend()
		)
	password_check = getpass.getpass('Re-Enter password:').encode()
	try:
		kdf2.verify(password_check, key_orig)
	except:
		print("Passwords don't match")
		return initialize_db()
	'''
	print("Password Saved, Creating Keys...")

	return create_keys(key_orig, salt)

	# Return length of 64 bytes of key_orig+salt
	# Return length of 88 for:
	# base64.urlsafe_b64encode(key_orig+salt)


def depreciated_decrypt_file(s_hash, data):
	password = getpass.getpass('Password:').encode()
	kdf1 = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=s_hash[-SALT_LENGTH:],
			iterations=N_ITERATIONS,
			backend=default_backend()
		)
	kdf1.verify(s_hash[:-SALT_LENGTH], )
	key = base64.urlsafe_b64encode(kdf.derive(password))
	f = Fernet(key)

	try:
		decrypted_db = f.decrypt(data)
		return decrypted_db
	except:
		print("Wrong password...")
		decrypt_file(data)

def startup(filename):
	if(os.path.exists(filename)):
		data = None
		with open(filename, 'rb') as f:
			data = f.read()
		if(len(data) > 0):
			validate_db = data[:5]
			headers = data[5:117]
			content = data[117:]

			if(validate_db != F_CHECK):
				print("File Not encrypted with script")
				exit()
			else:
				return (headers, content)
	return (b'', b'')

def decrypt_file(key, iv, ct, filename):

	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	pt = decryptor.update(ct) + decryptor.finalize()

	unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
	pt = unpadder.update(pt) + unpadder.finalize()

	with open(filename, 'wb') as file:
		file.write(pt)


def encrypt_and_save(key, iv, header, filename):
	with open(filename, 'rb') as f:
		pt = f.read()

	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	#enc_data = encryptor.update(pad(pt).encode()) + encryptor.finalize()

	padder = padding.PKCS7(BLOCK_SIZE).padder()
	padded_data = padder.update(pt) + padder.finalize()
	enc_data = encryptor.update(padded_data) + encryptor.finalize()

	with open(filename, 'wb') as file:
		file.write(F_CHECK)
		file.write(header)
		file.write(enc_data)
	logging.debug("Saved Password File...")

def main():

	#Command Line Arg Setup
	import argparse
	parser = argparse.ArgumentParser(description="Password File Encryptor")
	parser.add_argument("-f", "--file",action="store", help="File to encrypt or decrypt")
	parser.add_argument("-e", "--encrypt", action="store_true",
							help="Specify to encrypt file")
	parser.add_argument("-d", "--decrypt", action="store_true",
							help="Specify to decrypt file")
	args = parser.parse_args()
	aes_key = None
	password_dict = {}

	if args.file != None:
		if not os.path.exists(args.file):
			logging.error("Error: File does not exist...")
			exit()

		if args.encrypt:
			aes_key, file_header = setup()
			encrypt_and_save(aes_key, file_header[96:], file_header, args.file)
			print("File Successfully Encrypted")
		elif args.decrypt:
			file_header, enc_content  = startup(args.file)

			salt = file_header[:32] #32
			auth_check = file_header[32:64] #32
			enc_aes = file_header[64:96] #32
			iv = file_header[96:] #16

			aes_key = decrypt_aes_key(auth_check, salt, enc_aes, iv)
			password_dict = decrypt_file(aes_key, iv, enc_content, args.file)

			print("Filed Successfully Decrypted")
		else:
			print("Action not specified, specify -e (encryption) or -d (decryption)")



if __name__ == "__main__":
	main()