import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet

# Generate or load encryption key
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.encryption_key)

# Initialize in-memory storage and failed attempts
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("\U0001F512 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("\U0001F3E0 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("\U0001F4C2 Store Data Securely")
    data_id = st.text_input("Enter a unique Data ID (e.g., user1_data):")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if data_id and user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("\u2705 Data stored securely!")
        else:
            st.error("\u26A0\uFE0F All fields are required!")

elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.authenticated:
        st.warning("\U0001F512 Too many failed attempts! Please reauthorize from the Login Page.")
    else:
        st.subheader("\U0001F50D Retrieve Your Data")
        data_id = st.text_input("Enter Data ID:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if data_id in st.session_state.stored_data and passkey:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"\u2705 Decrypted Data: {decrypted_text}")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"\u274C Incorrect passkey! Attempts remaining: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("\U0001F512 Too many failed attempts! Redirecting to Login Page...")
                        st.experimental_rerun()
            else:
                st.error("\u26A0\uFE0F Invalid Data ID or Passkey!")

elif choice == "Login":
    st.subheader("\U0001F511 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure method for production
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("\u2705 Reauthorized successfully! Redirecting to Retrieve Data...")
            st.rerun()
        else:
            st.error("\u274C Incorrect password!")
