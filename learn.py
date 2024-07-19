from cryptography.fernet import Fernet
import getpass
import json
import os

def genkey():
    key = Fernet.generate_key()
    with open("key.key", "wb") as keysaved:
        keysaved.write(key)
    
def load_key():
    return open("key.key", "rb").read()

def encryptd(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decryptd(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

def addpass(service, username, password, key):
    encrypted_password = encryptd(password, key)
    entry = {
        "service": service,
        "username": username,
        "password": encrypted_password.decode()
    }
    if os.path.exists("passwords.txt"):
        with open("passwords.txt", "r") as file:
            data = json.load(file)
    else:
        data = []
    data.append(entry)
    with open("passwords.txt", "w") as file:
        json.dump(data, file)

def getspass(service, key):
    if os.path.exists("passwords.txt"):
        with open("passwords.txt", "r") as file:
            data = json.load(file)
        for entry in data:
            if entry["service"] == service:
                decrypted_password = decryptd(entry["password"].encode(), key)
                return entry["username"], decrypted_password
    return None, None

def main():
    if not os.path.exists("key.key"):
        genkey()
    key = load_key()
    
    while True:
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            service = input("Enter the service name: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            addpass(service, username, password, key)
            print("Password added successfully!")
        elif choice == "2":
            service = input("Enter the service name: ")
            username, password = getspass(service, key)
            if username:
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                print("Service not found!")
        elif choice == "3":
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()