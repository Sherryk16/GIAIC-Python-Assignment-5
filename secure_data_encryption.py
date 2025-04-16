import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken



if 'fernet_key' not in st.session_state:
    st.session_state['fernet_key'] = Fernet.generate_key()
cipher = Fernet(st.session_state['fernet_key'])

if 'data_store' not in st.session_state:
    st.session_state['data_store'] = {}  
if 'fail_attempts' not in st.session_state:
    st.session_state['fail_attempts'] = 0


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(message, passkey):
    """Encrypts the message and stores the token with the hashed passkey."""
    token = cipher.encrypt(message.encode()).decode()
    st.session_state['data_store'][token] = hash_passkey(passkey)
    return token

def decrypt_data(token, passkey):
    """Attempts to decrypt the token if it exists and passkey matches."""
    data_store = st.session_state['data_store']
    if token not in data_store:
        return None, "Token not recognized."
    
    if data_store[token] != hash_passkey(passkey):
        st.session_state['fail_attempts'] += 1
        return None, "Incorrect passkey."
    
    try:
        plaintext = cipher.decrypt(token.encode()).decode()
        st.session_state['fail_attempts'] = 0  # reset on success
        return plaintext, None
    except InvalidToken:
        st.session_state['fail_attempts'] += 1
        return None, "Invalid token format."


def home_page():
    st.title("🔐 Secure Data Vault")
    st.markdown("Store and retrieve your sensitive data with encryption. Use the sidebar to navigate between options.")

def store_page():
    st.header("📥 Store Data")
    data = st.text_area("Enter the text you want to encrypt:")
    passkey = st.text_input("Enter a passkey to secure your data:", type="password")
    
    if st.button("Encrypt & Store"):
        if not data or not passkey:
            st.error("Both data and passkey are required.")
        else:
            token = encrypt_data(data, passkey)
            st.success("✅ Data stored securely!")
            st.markdown("**Your encrypted token (save this to decrypt your data later):**")
            st.code(token, language="text")

def retrieve_page():
    st.header("🔓 Retrieve Data")
    
    if st.session_state['fail_attempts'] >= 3:
        st.error("Too many failed attempts. Please use the Login page to reset.")
        login_page()
        return
    
    token = st.text_area("Paste your encrypted token here:")
    passkey = st.text_input("Enter your passkey to decrypt the data:", type="password")
    
    if st.button("Decrypt"):
        if not token or not passkey:
            st.error("Both fields are required.")
        else:
            decrypted, err = decrypt_data(token, passkey)
            if decrypted:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Data:", decrypted, height=150)
            else:
                remaining = 3 - st.session_state['fail_attempts']
                st.error(f"{err} | Attempts left: {remaining}")

def login_page():
    st.header("🔑 Login to Reauthorize")
    admin_pass = st.text_input("Enter the master password:", type="password")
    
    if st.button("Login"):
        if admin_pass == "admin123": 
            st.session_state['fail_attempts'] = 0
            st.success("✅ Reauthorized successfully. You may now decrypt your data.")
        else:
            st.error("❌ Incorrect master password.")


pages = {
    "Home": home_page,
    "Store Data": store_page,
    "Retrieve Data": retrieve_page,
    "Login": login_page
}

st.sidebar.title("📚 Navigation")
selection = st.sidebar.radio("Go to", list(pages.keys()))
pages[selection]()
