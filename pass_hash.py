import hashlib

#To convert your password to a hashed password, enter the desired password when prompted
#Copy and paste the output to the HASHED_ADMIN variable in the main.py file

password = input("Please enter your password: ")

print(hashlib.sha256(password.encode()).hexdigest())