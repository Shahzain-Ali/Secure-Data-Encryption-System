import streamlit as st
from cryptography.fernet import Fernet
import hashlib


st.title("🔒 Secure Data Encryption System")

# Use session state to persist the key across reruns
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)
    st.session_state.store_data = {}
    st.session_state.attempts = 0

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home Page"
    

cipher = st.session_state.cipher

pages_lst = ["Home Page", "Store Data", "Retrieve Data", "Login"]


selected_page = st.sidebar.selectbox('Select Page', pages_lst, index=pages_lst.index(st.session_state.current_page))
st.session_state.current_page = selected_page


def encrypted_data(text):
    return cipher.encrypt(text.encode())

def hash_passkey(password):
    return hashlib.sha256(password.encode()).hexdigest()

def decrypted_data(encrypted_bytes):
    return cipher.decrypt(encrypted_bytes).decode()

if 'master_hash_password' not in st.session_state:
    new_password = st.text_input("Enter a password for authorizarion:",type="password")
    if new_password:
        st.session_state.master_hash_password = hash_passkey(new_password)
        st.success('Authorization password is set!✅')

def verify_user(user_password,hash_password):
    convert_verify_password = hash_passkey(user_password)
    return convert_verify_password == hash_password

if selected_page == "Home Page":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    # Display warning about key persistence
    st.warning("Note: Encryption keys are regenerated when the app restarts. Data will be lost on restart.")

elif selected_page == "Store Data":
    user_data = st.text_area("Enter text")

    # key parameter telling Streamlit that these are different input fields, which will prevent the browser from 
    # auto-filling the same password across pages.

    user_password = st.text_input("Enter password", type="password", key='store_password') 

    if st.button("Store Data"):
        if user_data and user_password:
            encrypted_bytes = encrypted_data(user_data)
            hashed_password = hash_passkey(user_password)
            
            st.session_state.store_data[encrypted_bytes] = {
                "encrypted_bytes": encrypted_bytes,
                "password": hashed_password
            }

            st.success("✅ Data stored successfully!")
        else:
            st.error("❌ Required both text and password!")

elif selected_page == "Retrieve Data":
    user_retrieve_password = st.text_input("Enter password", type="password", key='retrieve_password')
    if st.button("Retrieve Data"):
        if not st.session_state.authenticated:
            st.warning("🚫 You must login first to access this page!")
            st.session_state.current_page = "Login" 
            st.stop()


        elif st.session_state.store_data:
            hashed_password = hash_passkey(user_retrieve_password)
            found = False
            
            for key, value in st.session_state.store_data.items():
                if value['password'] == hashed_password:
                    original_text = decrypted_data(value['encrypted_bytes'])
                    st.success("Data retrieved successfully!")
                    st.write('Your data:', original_text)
                    found = True
                    st.session_state.attempts = 0
                    break
            
            if not found:
                st.session_state.attempts += 1
                if st.session_state.attempts < 3:
                    st.warning(f'{3 - st.session_state.attempts} attempts remaining')
                else:
                    st.warning("🔒Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.authenticated = False
                    st.session_state.current_page = "Login"
                    st.stop()
        else:
            st.warning('First store your data securely!')

elif selected_page == "Login":
    st.subheader('Check that you are a authorized user or not!')
    login_password = st.text_input('Enter a password',type="password")
    if st.button('login'):
        if login_password:
            verification = verify_user(login_password,st.session_state.master_hash_password)
            if verification == True:
                st.success('✅Login successfully!')
                st.session_state.authenticated = True

            else:
                st.error('❌Incorrect password!')
        else:
            st.warning('First enter the login password!')   
        
st.text("🔒 Developed by Shahzain Ali")