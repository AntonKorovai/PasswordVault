import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ZeroKnowledgeEngine:
    def __init__(self):
        self.KEY_LENGTH = 32#byte = 256 bit
        self.ITERATIONS = 600000 

    def derive_key(self, master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        if salt is None:#do not allow reinbow table attack
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC( #(Password-Based Key Derivation Function 2 with Hash-based Message Authentication Code)
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        key = kdf.derive(master_password.encode())
        return key, salt

    def generate_keypair(self) -> tuple[bytes, bytes]:#is used for authentication purposes
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return priv_pem, pub_pem

   

    def sign_challenge(self, private_pem: bytes, challenge: str) -> str:#allow the user to demonstrate the possession of the private ket and to pass the challange
        priv = serialization.load_pem_private_key(private_pem, password=None)
        firma = priv.sign(challenge.encode())
        return base64.b64encode(firma).decode('utf-8')

    def verify_challenge(self, public_pem: bytes, challenge: str, signature_b64: str) -> bool:#the server takes the users pub key and verifies if the signed challenge is the same with the original one
        try:
            pub = serialization.load_pem_public_key(public_pem)
            firma_bytes = base64.b64decode(signature_b64)
            pub.verify(firma_bytes, challenge.encode())
            return True
        except Exception:
            return False

    def encrypt_data(self, aes_key: bytes, data: dict) -> dict:
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_data(self, aes_key: bytes, encrypted_payload: dict) -> dict:#this one uses a symmetric key too.
        aesgcm = AESGCM(aes_key)
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    


    def encrypt_with_public_key(self, recipient_public_pem: bytes, secret_message: str) -> dict:
        recipient_pub_key = serialization.load_pem_public_key(recipient_public_pem)
        ephemeral_priv_key = x25519.X25519PrivateKey.generate()
        ephemeral_pub_key = ephemeral_priv_key.public_key()
        
        raw_shared_secret = ephemeral_priv_key.exchange(recipient_pub_key)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=None,
            info=b"vault-share-key-derivation",
        )
        aes_key = hkdf.derive(raw_shared_secret)#the secret is transformed into 256 bit key
        
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, secret_message.encode(), None)
        

        ephemeral_pub_pem = ephemeral_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "ephemeral_public_key": ephemeral_pub_pem.decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_with_private_key(self, my_private_pem: bytes, encrypted_share: dict) -> str:
        my_priv_key = serialization.load_pem_private_key(my_private_pem, password=None)
        ephemeral_pub_key = serialization.load_pem_public_key(encrypted_share["ephemeral_public_key"].encode('utf-8'))
        
        raw_shared_secret = my_priv_key.exchange(ephemeral_pub_key)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=None,
            info=b"vault-share-key-derivation",
        )
        aes_key = hkdf.derive(raw_shared_secret)
        
        aesgcm = AESGCM(aes_key)
        nonce = base64.b64decode(encrypted_share["nonce"])
        ciphertext = base64.b64decode(encrypted_share["ciphertext"])
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    
    
    def generate_encryption_keypair(self) -> tuple[bytes, bytes]:#is used for exchanging symmetric key purposes
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return priv_pem, pub_pem