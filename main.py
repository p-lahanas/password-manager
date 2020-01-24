import hashlib
import sqlite3
import os
import base64
import sys  
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

#default password is Peter change this by running the pass_hash.py file
HASHED_ADMIN= 'ea72c79594296e45b8c2a296644d988581f58cfac6601d122ed0a8bd7c02e8bf'


print(r"""   
#####################################################################################                                        
       _                  _               _            _                _          
      /\ \               /\ \            _\ \         /\ \             / /\        
     /  \ \____         /  \ \          /\__ \        \_\ \           / /  \       
    / /\ \_____\       / /\ \ \        / /_ \_\       /\__ \         / / /\ \      
   / / /\/___  /      / / /\ \_\      / / /\/_/      / /_ \ \       / / /\ \ \     
  / / /   / / /      / /_/_ \/_/     / / /          / / /\ \ \     / / /  \ \ \    
 / / /   / / /      / /____/\       / / /          / / /  \/_/    / / /___/ /\ \   
/ / /   / / /      / /\____\/      / / / ____     / / /          / / /_____/ /\ \  
\ \ \__/ / /      / / /______     / /_/_/ ___/\  / / /          / /_________/\ \ \ 
 \ \___\/ /      / / /_______\   /_______/\__\/ /_/ /          / / /_       __\ \_\
  \/_____/       \/__________/   \_______\/     \_\/           \_\___\     /____/_/      
#####################################################################################
""")
print("...a simple password manager created by Peter Lahanas\n")

user = input("Please enter your master password: ")

while hashlib.sha256(user.encode()).hexdigest() != HASHED_ADMIN:
    user = input("Please enter your master password: ")
    
connect = sqlite3.connect("users.db")
c = connect.cursor()


def hash_info(service_name, admin_pass):
    return hashlib.sha256(service_name.lower().encode() + user.lower().encode()).hexdigest()

def get_key(admin_pass, salt):
    password = admin_pass.encode()
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000, default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def check_services(service_name, admin_pass):
    service_name = hash_info(service_name, admin_pass)
    all_services = c.execute('SELECT servicename from user')
    
    for service in all_services:
        if service[0] == service_name:
            return False

    return True

def add_password(service_name, admin_pass, service_pass):
    f = Fernet(get_key(admin_pass, get_salt()))
    c.execute("""CREATE TABLE IF NOT EXISTS user(
                    servicename text,
                    servicepassword text                  
                    )"""
                    )
    hashed_service = hash_info(service_name, admin_pass)
    encrypted_pass = f.encrypt(service_pass.encode())
    info = (hashed_service, encrypted_pass) 
    c.execute("INSERT INTO user VALUES (?,?)", info)
    connect.commit()

def override_password(service_name, admin_pass, service_pass):
    f = Fernet(get_key(admin_pass, get_salt()))
    hashed_service = hash_info(service_name, admin_pass)
    encrypted_pass = f.encrypt(service_pass.encode())
    c.execute('UPDATE user SET servicepassword = ? WHERE servicename =?', (encrypted_pass, hashed_service))
    connect.commit()

def get_password(service_name, admin_pass):
    hashed_service = hash_info(service_name, admin_pass)
    try:
        c.execute("SELECT * FROM user WHERE servicename=?", (hashed_service,))
        rows = c.fetchall()
        encrypted = bytes(rows[0][1])
        f = Fernet(get_key(admin_pass, get_salt()))
        password = f.decrypt(encrypted)
        password = str(password)
        print("Password: " + password.strip('b'))

    except ImportError:
       print("Check that all libraries are correctly installed")
    except IndexError:
        print("Service does not exist...")
    except:
        print('An error has occured ', sys.exc_info()[0])

def get_salt():
    with open("salt.txt", 'r') as salt:
        salt = salt.readlines()[0].strip('"')
        return salt[1:].encode()


while True:
    print("\nCommands: r = retrieve password, s = set password, q = quit")
    selection = input(': ')
    if selection == 'r':
        service = input("Please enter the name of the service: ")
        get_password(service, user)
    
    elif selection == 's':
        service = input("Please enter the service name: ")
        if check_services(service, user):
            password = input("Please enter the password for the service: ")
            add_password(service, user, password)
        else:
            x = input("Service password already exists would like to override the password? (y/n)")
            if x == 'y':
                password = input("Please enter the password for the service: ")
                override_password(service, user, password)
            else:
                print("Cancelled...")
    
    elif selection == 'q':
        print("Quitting...")
        break

    else:
        print("Invalid input")



