import base64, json
import os, getpass, logging
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.DEBUG)

SALT_LENGTH = 32
N_ITERATIONS = 1000000
F_CHECK = "TPASS".encode() #Len: 5
BLOCK_SIZE = 16


pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def get_storage_file():
	home = os.path.expanduser('~')
	return os.path.join(home, ".tpass")

def delete_pass_file():
	filename = get_storage_file()
	if os.path.exists(filename):
		os.remove(filename)

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
		quit()
		# NOTE: Fails if you retry password 
		#decrypt_aes_key(hash_check, salt, enc_key, iv)

	cipher = Cipher(algorithms.AES(hashed_pass[:32]), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	return decryptor.update(enc_key) + decryptor.finalize()

def setup_db():
	password = getpass.getpass('Enter a password:').encode()
	salt = os.urandom(SALT_LENGTH)
	kdf1 = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=64,
			salt=salt,
			iterations=N_ITERATIONS,
			backend=default_backend()
		)
	key_orig = kdf1.derive(password)
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
		initialize_db()
	
	print("Password Saved, Creating Keys...")

	return create_keys(key_orig, salt)

	# Return length of 64 bytes of key_orig+salt
	# Return length of 88 for:
	# base64.urlsafe_b64encode(key_orig+salt)

def decrypt_database(s_hash, data):
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
		decrypt_database(data)

def initialize_db(db_file):
	with open(db_file, 'wb+') as file:
		file.write(F_CHECK)

def db_startup():
	db_file = get_storage_file()
	if(os.path.exists(db_file)):
		data = None
		with open(db_file, 'rb') as f:
			data = f.read()
		if(len(data) > 0):
			validate_db = data[:5]
			headers = data[5:117]
			content = data[117:]

			if(validate_db != F_CHECK):
				print("Not Valid Password File")
				response = input("Do You Want to Initialize a New Password File (y/n)")
				if(response == 'y'):
					initialize_db(db_file)
					return (b'', b'')
				else:
					print("Bye...")
					exit()
			else:
				return (headers, content)
		else:
			initialize_db(db_file)
			return (b'', b'')
	else:
		initialize_db(db_file)
		return (b'', b'')

def decrypt_store(key, iv, ct):
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	return json.loads(unpad(decryptor.update(ct) + decryptor.finalize()).decode())

def encrpyt_and_save(key, iv, header, pt):
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	enc_data = encryptor.update(pad(pt).encode()) + encryptor.finalize()
	with open(get_storage_file(), 'wb') as file:
		file.write(F_CHECK)
		file.write(header)
		file.write(enc_data)
	logging.debug("Saved Password File...")

def main():
	aes_key = None
	password_dict = {}

	file_header, enc_content  = db_startup()
	if(file_header != b'' and enc_content != b''):
		logging.debug("file_header_size: {}, len(ec): {}".format(len(file_header), len(enc_content)))
		logging.debug("Found Valid DB")

		#file header length = 112
		salt = file_header[:32] #32
		auth_check = file_header[32:64] #32
		enc_aes = file_header[64:96] #32
		iv = file_header[96:] #16

		aes_key = decrypt_aes_key(auth_check, salt, enc_aes, iv)
		password_dict = decrypt_store(aes_key, iv, enc_content)
		print("Successfuly loaded passwords")
		
	else:
		logging.debug("No Data in DB... Setting up a new one")
		aes_key, file_header = setup_db()
		encrpyt_and_save(aes_key, file_header[96:], file_header, json.dumps(password_dict))
		print("Password Storage Set Up and Secure")

	#Everything beyond this point should be loaded correctly




if __name__ == "__main__":
	main()