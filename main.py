import streamlit as st
import hashlib
import json
import os
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import streamlit.components.v1 as components

# Constants
DATA_FILE = "users_data.json"
SALT = b"streamlit_salt_2024"

# Load data from JSON
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

# Hash passkey
def hash_passkey(passkey):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode())).decode()

# Derive encryption key
def derive_fernet_key(passkey):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# Encrypt and decrypt functions
def encrypt_data(data, passkey):
    key = derive_fernet_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(cipher_text, passkey):
    try:
        key = derive_fernet_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(cipher_text.encode()).decode()
    except:
        return None

# Init session state
if "users" not in st.session_state:
    st.session_state.users = load_data()

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Lockout check
def is_locked_out():
    return time.time() < st.session_state.lockout_time

# Sidebar
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if st.session_state.current_user:
    if st.sidebar.button("🚪 Logout"):
        st.session_state.current_user = None
        st.success("🔒 You have been logged out.")

# Home Page
if choice == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.markdown("""
    This system allows multiple users to securely:
    - Store encrypted data using a passkey.
    - Retrieve data only with the correct passkey.
    - Get locked out for 60 seconds after 3 failed attempts.
    - Store data persistently in a JSON file.
    """)

# Register
elif choice == "Register":
    st.subheader("🧑‍💻 Register New User")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if username in st.session_state.users:
            st.error("❌ Username already exists.")
        elif username and password:
            st.session_state.users[username] = {
                "password": hash_passkey(password),
                "data": []
            }
            save_data(st.session_state.users)
            st.success("✅ User registered successfully!")
        else:
            st.error("⚠️ Please fill in both fields.")

# Login
elif choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = st.session_state.users.get(username)
        if user and user["password"] == hash_passkey(password):
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid username or password.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("⚠️ Please log in first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data_input = st.text_area("Enter your sensitive data", key="data_input")
        passkey = st.text_input("🔑 Enter Passkey to encrypt and save", type="password")

        if st.button("🔐 Encrypt & Save"):
            if data_input and passkey:
                encrypted = encrypt_data(data_input, passkey)
                hashed_pass = hash_passkey(passkey)

                # Save encrypted data
                st.session_state.users[st.session_state.current_user]["data"].append({
                    "encrypted_text": encrypted,
                    "passkey": hashed_pass
                })
                save_data(st.session_state.users)

                st.success("✅ Data encrypted and stored.")

                # Add copy button
                components.html(f"""
<textarea id=\"encryptedText\" style=\"width:100%; height:120px;\">{encrypted}</textarea>
<button onclick=\"navigator.clipboard.writeText(document.getElementById('encryptedText').value)\">📋 Copy Encrypted Text</button>
""", height=180)

            else:
                st.error("⚠️ Please provide both the data and the passkey.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("⚠️ Please log in first.")
    elif is_locked_out():
        remaining = int(st.session_state.lockout_time - time.time())
        st.warning(f"⏳ Locked out due to failed attempts. Try again in {remaining} seconds.")
    else:
        st.subheader("🔍 Retrieve Data")
        encrypted_input = st.text_area("Paste Encrypted Data")
        passkey = st.text_input("Enter Your Passkey", type="password")

        if st.button("Decrypt"):
            user_data = st.session_state.users[st.session_state.current_user]["data"]
            hashed_pass = hash_passkey(passkey)
            for entry in user_data:
                if entry["encrypted_text"] == encrypted_input and entry["passkey"] == hashed_pass:
                    result = decrypt_data(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decrypted Data:")
                        st.text_area("Decrypted Output", value=result, height=120)
                        st.session_state.failed_attempts = 0
                        break
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Decryption failed. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. You are locked out for 60 seconds.")
                    st.session_state.lockout_time = time.time() + 60
