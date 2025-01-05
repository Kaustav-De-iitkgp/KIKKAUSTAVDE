import hashlib
import os

def generate_salt():
    return os.urandom(16)
    
def hash(password, salt):
    password_salt = password.encode('utf-8') + salt
    return hashlib.sha256(password_salt).hexdigest()

user_data = {}

def sign_up():
    username = input("Enter username: ")
    password = input("Enter password: ")
    salt = generate_salt()
    hashed_password = hash(password, salt)
    user_data[username] = {'hashed_password': hashed_password, 'salt': salt}
    print(f"Sign up successful! Welcome, {username}.")

def log_in():
    username = input("Enter username: ")
    if username not in user_data:
        print("Username not found. Please sign up first.")
        return
    password = input("Enter password: ")
    stored_salt = user_data[username]['salt']
    stored_hashed_password = user_data[username]['hashed_password']
    hashed_input_password = hash(password, stored_salt)
    if hashed_input_password == stored_hashed_password:
        print("Login successful!")
    else:
        print("Invalid username or password. Please try again.")

def main():
    while True:
        print("\nSelect an option:")
        print("1. Sign Up")
        print("2. Log In")
        print("3. Exit")
        
        choice = input("Enter your choice (1/2/3): ")
        
        if choice == '1':
            sign_up()
        elif choice == '2':
            log_in()
        elif choice == '3':
            print("Exiting the application. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
