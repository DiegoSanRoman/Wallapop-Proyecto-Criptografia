import tkinter as tk
import json
import os

def register():
    username = username_entry.get()
    password = password_entry.get()

    user_data = {
        'username': username,
        'password': password
    }

    if os.path.exists('users.json'):
        with open('users.json', 'r', encoding="utf-8") as file:
            try:
                existing_data = list(json.load(file))
            except json.JSONDecodeError:
                existing_data = []
    else:
        existing_data = []

    existing_data.append(user_data)

    with open('users.json', 'w', encoding="utf-8") as file:
        json.dump(existing_data, file)

    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

    print("Registration successful. You are now logged in.")

def login():
    username = username_entry.get()
    password = password_entry.get()

    if os.path.exists('users.json'):
        with open('users.json', 'r', encoding="utf-8") as file:
            try:
                existing_data = list(json.load(file))
            except json.JSONDecodeError:
                existing_data = []

        for user in existing_data:
            if user['username'] == username and user['password'] == password:
                print("Login successful.")
                return

    print("Login failed. Incorrect username or password.")

root = tk.Tk()

username_label = tk.Label(root, text="Username")
username_label.pack()

username_entry = tk.Entry(root)
username_entry.pack()

password_label = tk.Label(root, text="Password")
password_label.pack()

password_entry = tk.Entry(root, show="*")
password_entry.pack()

register_button = tk.Button(root, text="Register", command=register)
register_button.pack()

login_button = tk.Button(root, text="Login", command=login)
login_button.pack()

root.mainloop()