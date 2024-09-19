import os
import json
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def register():
    username = username_entry.get()
    password = password_entry.get().encode()

    if not username or not password:
        messagebox.showerror("Error", "Por favor, rellene todos los campos.")
        return

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password)

    user_data = {
        'username': username,
        'key': key.hex(),
        'salt': salt.hex()
    }

    try:
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
            json.dump(existing_data, file, indent=4)

        messagebox.showinfo("Éxito", "Registro exitoso.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al guardar datos: {e}")

def login():
    username = username_entry.get()
    password = password_entry.get().encode()

    if not username or not password:
        messagebox.showerror("Error", "Por favor, rellene todos los campos.")
        return

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
                    messagebox.showinfo("Éxito", "Inicio de sesión exitoso.")
                    return
                except:
                    messagebox.showerror("Error", "Contraseña incorrecta.")
                    return
        messagebox.showerror("Error", "Nombre de usuario no encontrado.")
    else:
        messagebox.showerror("Error", "No hay usuarios registrados. Regístrese primero.")

# Interfaz gráfica mejorada
root = tk.Tk()
root.title("Registro e Inicio de Sesión")
root.configure(bg='#f0f0f0')
root.geometry("400x300")

# Estilos de ttk
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=6, relief="flat", background="#5a9")
style.map("TButton",
          background=[("active", "#479")])

# Etiqueta de bienvenida
welcome_label = tk.Label(root, text="Bienvenido al programa", bg='#f0f0f0', font=("Arial", 16, "bold"))
welcome_label.pack(pady=10)

# Etiqueta de instrucciones
option_label = tk.Label(root, text="Seleccione una opción:", bg='#f0f0f0', font=("Arial", 12))
option_label.pack(pady=5)

# Crear un Frame para los botones
button_frame = tk.Frame(root, bg='#f0f0f0')
button_frame.pack(pady=10)

# Botón de registro
register_button = ttk.Button(button_frame, text="Registrarse", command=register)
register_button.grid(row=0, column=0, padx=10)

# Botón de iniciar sesión
login_button = ttk.Button(button_frame, text="Iniciar sesión", command=login)
login_button.grid(row=0, column=1, padx=10)

# Etiqueta y campo de entrada para el nombre de usuario
username_label = tk.Label(root, text="Nombre de usuario", bg='#f0f0f0', font=("Arial", 12))
username_label.pack(pady=5)

username_entry = tk.Entry(root, font=("Arial", 12))
username_entry.pack(pady=5)

# Etiqueta y campo de entrada para la contraseña
password_label = tk.Label(root, text="Contraseña", bg='#f0f0f0', font=("Arial", 12))
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="*", font=("Arial", 12))
password_entry.pack(pady=5)

root.mainloop()
