# 🛡️ Python Assignment: Secure Data Encryption System Using Streamlit

## **Objective**  
Develop a **Streamlit-based secure data storage and retrieval system** where:  
- Users **store** data with a **unique passkey**.  
- Users **decrypt** data by providing the correct passkey.  
- **Multiple failed attempts** result in a **forced reauthorization (login page).**  
- The system operates **entirely in memory** without external databases.  

---

## **🔹 Requirements**  

### **1. Data Storage (In-Memory Dictionary)**
- Each entry is stored as:  
  ```python
  stored_data = {
      "user1_data": {"encrypted_text": "some_ciphertext", "passkey": "hashed_passkey"},
      ...
  }
  ```
- Passkeys must be hashed (e.g., **SHA-256**).  

### **2. Secure Encryption & Decryption**  
- Encrypt data using **Caesar cipher** or **Fernet (from cryptography library)**.  
- Decrypt only when the **correct passkey** is provided.  

### **3. Authentication & Security**
- Allow **three attempts** before forcing a **reauthorization/login page**.  
- Display **failed attempts** count.  

### **4. Streamlit UI (User-Friendly Interface)**
- **Home Page:** Options to **store new data** or **retrieve data**.  
- **Insert Data Page:**  
  - User enters **text** + **passkey**, and it’s stored securely.  
- **Retrieve Data Page:**  
  - User provides a **passkey** to **decrypt data**.  
  - If failed **3 times**, redirect to the **Login Page** for reauthorization.  
- **Login Page:** Simple login mechanism before retrying.  

---

## **🔹 Starter Code (Python + Streamlit)**  

```python
import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (this should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            global failed_attempts
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
```

---

## **🔹 Additional Challenges**
1. **Data Persistence**  
   - Store encrypted data in a **JSON file** instead of memory.  
   - Load data on app startup.  

2. **Advanced Security Features**  
   - **Time-based lockout** for failed attempts.  
   - Use **PBKDF2** hashing instead of SHA-256 for extra security.  

3. **Multi-User System**  
   - Allow **multiple users** to store and retrieve their own data.  
   - Use a **user authentication system** with Streamlit.  

---

## **🔹 Why This Assignment is Challenging**
✅ **Requires Control Flow Mastery:** Loops, conditions, and validation checks.  
✅ **Uses Multiple Data Types:** Strings, dictionaries, lists, and encryption handling.  
✅ **Teaches Encryption Basics:** Symmetric encryption (Fernet).  
✅ **Integrates Streamlit:** Real-world UI development with Python.  
✅ **Enhances Debugging Skills:** Handling incorrect inputs, failed attempts, and redirections.  

Good luck, and happy coding! 🚀  

Useful Links for learning:
1.  [Fernet (symmetric encryption) using Cryptography module in Python](https://www.geeksforgeeks.org/fernet-symmetric-encryption-using-cryptography-module-in-python/)
2.  [hashlib module in Python](https://www.geeksforgeeks.org/hashlib-module-in-python/)


Once you are done submit this form ASAP:

https://forms.gle/tS7C3sr55tUZ36GY8 

Good luck! 🚀
