import requests
import json
import os
import getpass
from crypto_engine import ZeroKnowledgeEngine

BASE_URL = "http://127.0.0.1:8000"
engine = ZeroKnowledgeEngine()

session = {
    "username": None,
    "jwt_token": None,
    "aes_key": None,
    "id_priv": None,
    "enc_priv": None
}

def get_device_file(username):
    return f"{username}_device.json"

def save_device_data(username, password, id_priv, id_pub, enc_priv, enc_pub):
    aes_key, salt = engine.derive_key(password)
    secret_data = json.dumps({
        "id_priv": id_priv.decode('utf-8'),
        "enc_priv": enc_priv.decode('utf-8')
    })
    encrypted_secrets = engine.encrypt_data(aes_key, secret_data)
    data = {
        "id_pub": id_pub.decode('utf-8'),
        "enc_pub": enc_pub.decode('utf-8'),
        "salt": salt.hex(),
        "encrypted_secrets": encrypted_secrets
    }
    with open(get_device_file(username), "w") as f:
        json.dump(data, f)


def load_device_data(username, password):
    try:
        with open(get_device_file(username), "r") as f:
            data = json.load(f)
            
        salt_bytes = bytes.fromhex(data["salt"])
        aes_key, _ = engine.derive_key(password, salt=salt_bytes)
        
        try:
            secret_json = engine.decrypt_data(aes_key, data["encrypted_secrets"])
            secrets = json.loads(secret_json)
        except Exception:
            return None 
            
        return {
            "aes_key": aes_key,
            "id_priv": secrets["id_priv"].encode('utf-8'),
            "enc_priv": secrets["enc_priv"].encode('utf-8'),
            "id_pub": data["id_pub"].encode('utf-8'),
            "enc_pub": data["enc_pub"].encode('utf-8')
        }
    except FileNotFoundError:
        return None


def register():
    print("\n--- 📝 NEW USER REGISTRATION ---")
    username = input("Choose a username: ")

    
    if os.path.exists(get_device_file(username)):
        print("❌ This device already has data for this user. Please log in.")
        return

    password = getpass.getpass("Enter Master Password: ")
    if len(password) < 8:
        print("❌ The password must be at least 8 characters long to ensure key security.")
        return
    
    print("⏳ Generating cryptographic keys (this may take a few seconds)...")
    id_priv, id_pub = engine.generate_keypair()
    enc_priv, enc_pub = engine.generate_encryption_keypair()
    
    save_device_data(username, password, id_priv, id_pub, enc_priv, enc_pub)

    payload = {
        "username": username,
        "public_key_pem": id_pub.decode('utf-8'),
        "encryption_public_key_pem": enc_pub.decode('utf-8')
    }
    res = requests.post(f"{BASE_URL}/register", json=payload)
    
    if res.status_code == 200:
        print("✅ Registration completed! Your private keys have been secured on the device.")
    else:
        print(f"❌ Server error: {res.text}")

def login():
    print("\n--- 🔐 ZERO-KNOWLEDGE LOGIN ---")
    username = input("Username: ")
    
    if not os.path.exists(get_device_file(username)):
        print("❌ No data found on this device for the user. You must register.")
        return

    password = getpass.getpass("Master Password: ")
    device_data = load_device_data(username, password)
    
    if not device_data:
        print("❌ Incorrect Master Password! Cannot decrypt private keys on the device.")
        return

    print("⏳ Verifying identity with the server...")
    res_chal = requests.get(f"{BASE_URL}/auth/challenge/{username}")
    if res_chal.status_code != 200:
        print("❌ Error during challenge request.")
        return
        
    nonce = res_chal.json()["challenge"]
    firma = engine.sign_challenge(device_data["id_priv"], nonce)
    
    res_login = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "signature": firma})
    
    if res_login.status_code == 200:
        session["username"] = username
        session["jwt_token"] = res_login.json()["access_token"]
        session["aes_key"] = device_data["aes_key"]
        session["id_priv"] = device_data["id_priv"]
        session["enc_priv"] = device_data["enc_priv"]
        print("✅ Access granted! Welcome to your Vault.")
    else:
        print("❌ Server authentication failed (Invalid or expired signature).")

def get_decrypted_vault():
    headers = {"Authorization": f"Bearer {session['jwt_token']}"}
    res = requests.get(f"{BASE_URL}/vault", headers=headers)
    
    if res.status_code == 404:
        return {}
    elif res.status_code == 200:
        try:
            plaintext = engine.decrypt_data(session["aes_key"], res.json())
            return json.loads(plaintext)
        except Exception:
            print("❌ CANNOT DECRYPT THE VAULT! (The Master Password is incorrect or the data is corrupted)")
            return {}
    else:
        print("❌ Server connection error.")
        return {}

def save_encrypted_vault(vault_dict):
    headers = {"Authorization": f"Bearer {session['jwt_token']}"}
    plaintext = json.dumps(vault_dict)
    encrypted_payload = engine.encrypt_data(session["aes_key"], plaintext)
    
    res = requests.post(f"{BASE_URL}/vault", json=encrypted_payload, headers=headers)
    if res.status_code == 200:
        print("✅ Vault securely synchronized with the server.")
    else:
        print("❌ Error saving to the server.")

def view_vault():
    print("\n--- 🏦 YOUR PERSONAL VAULT ---")
    vault = get_decrypted_vault()
    if not vault:
        print("The vault is empty.")
    else:
        for servizio, password in vault.items():
            print(f"🔸 {servizio.upper()}: {password}")

def add_password():
    print("\n--- ➕ ADD CREDENTIAL ---")
    servizio = input("Service name (e.g. Netflix, Bank): ")
    password = input("Password to save: ")
    
    vault = get_decrypted_vault()
    vault[servizio] = password
    save_encrypted_vault(vault)

def share_password():
    print("\n--- 🤝 ZERO-KNOWLEDGE E2E SHARING ---")
    Receiver = input("Recipient username: ")
    
    headers = {"Authorization": f"Bearer {session['jwt_token']}"}
    res_key = requests.get(f"{BASE_URL}/users/{Receiver}/key", headers=headers)
    
    if res_key.status_code != 200:
        print("❌ User not found or network error.")
        return
        
    dest_pub_key = res_key.json()["enc_public_key"].encode('utf-8')
    servizio = input("Service to share (title): ")
    password = input("Password to send: ")
    
    PlainText_Msg = json.dumps({"servizio": servizio, "password": password})
    
    Encrypted_Msg = engine.encrypt_with_public_key(dest_pub_key, PlainText_Msg)
    
    # is mathematically certain that we sent it, preventing spoofing by the server.
    dati_da_firmare = f"{Receiver}:{Encrypted_Msg['ephemeral_public_key']}:{Encrypted_Msg['nonce']}:{Encrypted_Msg['ciphertext']}"
    Sender_Dgtl_Sgn = engine.sign_challenge(session["id_priv"], dati_da_firmare)
    
    payload = {
        "recipient": Receiver,
        "ephemeral_public_key": Encrypted_Msg["ephemeral_public_key"],
        "nonce": Encrypted_Msg["nonce"],
        "ciphertext": Encrypted_Msg["ciphertext"],
        "sender_signature": Sender_Dgtl_Sgn
    }
    
    res_share = requests.post(f"{BASE_URL}/share", json=payload, headers=headers)
    if res_share.status_code == 200:
        print(f"✅ Package encrypted, signed, and successfully sent to {Receiver}!")
    else:
        print("❌ Error during sending.")



def view_inbox():
    print("\n--- 📥 RECEIVED MESSAGES INBOX ---")
    headers = {"Authorization": f"Bearer {session['jwt_token']}"}
    res = requests.get(f"{BASE_URL}/share", headers=headers)
    
    if res.status_code != 200:
        print("❌ Error retrieving messages.")
        return
        
    inbox = res.json().get("inbox", [])
    if not inbox:
        print("No new messages.")
        return
        
    for idx, msg in enumerate(inbox):
        print(f"\nMessage {idx + 1} from: {msg['sender']} (On {msg['timestamp']})")
        
        res_sender = requests.get(f"{BASE_URL}/users/{msg['sender']}/identity_key", headers=headers)
        if res_sender.status_code != 200:
            print("❌ Cannot retrieve the sender's key.")
            continue
            
        sender_pub_key = res_sender.json()["public_key"].encode('utf-8')
        
        dati_firmati = f"{session['username']}:{msg['ephemeral_public_key']}:{msg['nonce']}:{msg['ciphertext']}"
        if not engine.verify_challenge(sender_pub_key, dati_firmati, msg['sender_signature']):
            print("❌ WARNING: Invalid E2E signature! The message might be fake or tampered with by the server.")
            continue
            
        try:
            chiaro = engine.decrypt_with_private_key(session["enc_priv"], msg)
            dati = json.loads(chiaro)
            print(f"🔓 {dati['servizio'].upper()}: {dati['password']}")
        except Exception:
            print("❌ Cannot decrypt the message.")


def main():
    print("="*50)
    print("🛡️ ZERO-KNOWLEDGE PASSWORD VAULT CLI 🛡️")
    print("="*50)
    
    while True:
        if not session["jwt_token"]:
            print("\n1. Register")
            print("2. Login")
            print("3. Exit")
            scelta = input("Choose an option: ")
            
            if scelta == "1": register()
            elif scelta == "2": login()
            elif scelta == "3": break
            else: print("Invalid choice.")
        else:
            print(f"\n--- Logged in as: {session['username']} ---")
            print("1. View your Vault")
            print("2. Add new Password")
            print("3. Share a Password")
            print("4. Check Received Messages")
            print("5. Logout")
            scelta = input("Choose an option: ")
            
            if scelta == "1": view_vault()
            elif scelta == "2": add_password()
            elif scelta == "3": share_password()
            elif scelta == "4": view_inbox()
            elif scelta == "5":
                session["jwt_token"] = None
                session["aes_key"] = None
                session["id_priv"] = None
                session["enc_priv"] = None
                print("Logged out. Data removed from RAM.")
            else:
                print("Invalid choice.")

if __name__ == "__main__":
    main()