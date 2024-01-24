import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2

SALT_LENGTH = 16
KEY_LENGTH = 32
ITERATIONS = 1_000_000

def encrypt_note_content(note_content: str, password: str):
    note_content = note_content.encode()
    password = password.encode()

    salt = get_random_bytes(SALT_LENGTH)
    key = PBKDF2(password, salt, KEY_LENGTH, count = ITERATIONS, hmac_hash_module = SHA512)
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    note_content_base64 = base64.b64encode(note_content)
    note_ready = note_content_base64 + b'='*(16 - (len(note_content_base64) % 16))

    return base64.b64encode(cipher.encrypt(note_ready)).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode()


def decrypt_note_content(note_content_base64: str, password: str, salt_base64: str, init_vector_base64: str):
    note_content = base64.b64decode(note_content_base64)
    salt = base64.b64decode(salt_base64)
    iv = base64.b64decode(init_vector_base64)

    password = password.encode()
    
    key = PBKDF2(password, salt, KEY_LENGTH, count = ITERATIONS, hmac_hash_module = SHA512)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return base64.b64decode(cipher.decrypt(note_content)).decode()
