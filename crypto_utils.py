from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
import base64

class CryptoUtils:
    RSA_KEY_SIZE = 2048
    AES_KEY_SIZE = 32  # AES-256
    IV_SIZE = 16       # AES block size

    @staticmethod
    def generate_rsa_key_pair():
        key = RSA.generate(CryptoUtils.RSA_KEY_SIZE)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def encrypt_aes_cbc(data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_len = AES.block_size - len(data) % AES.block_size
        data += bytes([pad_len]) * pad_len
        return cipher.encrypt(data)

    @staticmethod
    def decrypt_aes_cbc(ciphertext, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)
        pad_len = data[-1]
        if pad_len > AES.block_size:
            raise ValueError("Invalid padding")
        return data[:-pad_len]

    @staticmethod
    def encrypt_session_key(session_key, public_key):
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA512)
        return cipher_rsa.encrypt(session_key)

    @staticmethod
    def decrypt_session_key(encrypted_session_key, private_key):
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA512)
        return cipher_rsa.decrypt(encrypted_session_key)

    @staticmethod
    def sign_metadata(metadata, private_key):
        rsa_key = RSA.import_key(private_key)
        h = SHA512.new(metadata.encode('utf-8'))
        signature = pkcs1_15.new(rsa_key).sign(h)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(metadata, signature, public_key):
        rsa_key = RSA.import_key(public_key)
        h = SHA512.new(metadata.encode('utf-8'))
        try:
            pkcs1_15.new(rsa_key).verify(h, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def calculate_hash(iv, ciphertext):
        h = SHA512.new()
        h.update(iv)
        h.update(ciphertext)
        return h.hexdigest()
