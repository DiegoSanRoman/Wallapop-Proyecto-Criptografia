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
        # Abrir el archivo y cargar los datos existentes
        with open('users.json', 'r', encoding="utf-8") as file:
            try:
                existing_data = list(json.load(file))
            except json.JSONDecodeError:
                existing_data = []  # Si el archivo está vacío o corrupto, inicializar como lista vacía
    else:
        existing_data = []

    # Añadir los nuevos datos
    existing_data.append(user_data)

    with open('users.json', 'w', encoding="utf-8") as file:
        json.dump(existing_data, file)

    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

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

root.mainloop()