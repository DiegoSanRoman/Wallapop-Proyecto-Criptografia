import os
import json
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def register():
    username = username_entry.get()
    password = password_entry.get().encode()

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password)

    user_data = {
        'username': username,
        'key': key.hex(),
        'salt': salt.hex()
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

    messagebox.showinfo("Success", "Registration successful. You are now logged in.")

def login():
    username = username_entry.get()
    password = password_entry.get().encode()

    if os.path.exists('users.json'):
        with open('users.json', 'r', encoding="utf-8") as file:
            try:
                existing_data = list(json.load(file))
            except json.JSONDecodeError:
                existing_data = []

        for user in existing_data:
            if user['username'] == username:
                salt = bytes.fromhex(user['salt'])
                kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
                try:
                    kdf.verify(password, bytes.fromhex(user['key']))
                    messagebox.showinfo("Success", "Login successful. You are now logged in.")
                    return
                except:
                    messagebox.showerror("Error", "Incorrect password. Please try again.")
                    return
        else:
            messagebox.showerror("Error", "Username not found. Please try again.")
    else:
        messagebox.showerror("Error", "No users registered. Please register first.")

root = tk.Tk()
root.configure(bg='light blue')

welcome_label = tk.Label(root, text="Bienvenido al programa", bg='light blue')
welcome_label.pack()

option_label = tk.Label(root, text="Seleccione una opción:", bg='light blue')
option_label.pack()

register_button = tk.Button(root, text="1. Registrarse", command=register, bg='blue', fg='white')
register_button.pack()

login_button = tk.Button(root, text="2. Iniciar sesión", command=login, bg='blue', fg='white')
login_button.pack()

username_label = tk.Label(root, text="Username", bg='light blue')
username_label.pack()

username_entry = tk.Entry(root)
username_entry.pack()

password_label = tk.Label(root, text="Password", bg='light blue')
password_label.pack()

password_entry = tk.Entry(root, show="*")
password_entry.pack()

root.mainloop()