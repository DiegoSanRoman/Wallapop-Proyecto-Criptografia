import os
import json
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from PIL import Image, ImageTk, \
    ImageSequence  # Librería para manejar GIF animado en tkinter


def register():
    username = username_entry.get()
    password = password_entry.get().encode()

    if not username or not password:
        messagebox.showerror("Error", "Por favor, rellene todos los campos.")
        return

    # Comprobar si el nombre de usuario ya existe
    if os.path.exists('users.json'):
        with open('users.json', 'r', encoding="utf-8") as file:
            try:
                existing_data = list(json.load(file))
                for user in existing_data:
                    if user['username'] == username:
                        messagebox.showerror("Error", "El nombre de usuario ya existe.")
                        return
            except json.JSONDecodeError:
                existing_data = []

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    key = kdf.derive(password)

    user_data = {
        'username': username,
        'key': key.hex(),
        'salt': salt.hex()
    }

    existing_data.append(user_data)

    with open('users.json', 'w', encoding="utf-8") as file:
        json.dump(existing_data, file, indent=4)

    messagebox.showinfo("Éxito", "Registro exitoso.")


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
                kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
                try:
                    kdf.verify(password, bytes.fromhex(user['key']))
                    username = username_entry.get()
                    open_success_window(username)  # Abrir la ventana de éxito
                    return
                except:
                    messagebox.showerror("Error", "Contraseña incorrecta.")
                    return
        messagebox.showerror("Error", "Nombre de usuario no encontrado.")
    else:
        messagebox.showerror("Error",
                             "No hay usuarios registrados. Regístrese primero.")



def open_success_window(username):
    # Cerrar la ventana de login
    root.destroy()

    # Crear nueva ventana
    success_window = tk.Tk()
    success_window.title("Inicio de sesión exitoso")
    success_window.geometry("400x400")
    success_window.configure(bg='#f0f0f0')

    # Mensaje de éxito
    success_label = tk.Label(success_window, text="¡Inicio de sesión exitoso!",
                             font=("Arial", 16, "bold"), bg='#f0f0f0')
    success_label.pack(pady=20)

    # Botones para Comprar y Vender
    buy_button = ttk.Button(success_window, text="Comprar objeto", command=lambda: buy_item(username))
    buy_button.pack(pady=10)

    sell_button = ttk.Button(success_window, text="Vender objeto", command=lambda: sell_item(username))
    sell_button.pack(pady=10)

    success_window.mainloop()


def buy_item(username):
    if os.path.exists('items.json'):
        with open('items.json', 'r', encoding='utf-8') as file:
            try:
                items = list(json.load(file))
            except json.JSONDecodeError:
                items = []
    else:
        items = []

    if not items:
        messagebox.showinfo("Información", "No hay objetos disponibles.")
        return

    # Ventana para comprar
    buy_window = tk.Toplevel()
    buy_window.title("Comprar objeto")
    buy_window.geometry("300x300")
    buy_window.configure(bg='#f0f0f0')

    buy_label = tk.Label(buy_window, text="Seleccione un objeto para comprar:",
                         bg='#f0f0f0', font=("Arial", 12))
    buy_label.pack(pady=10)

    # Lista de objetos disponibles
    item_listbox = tk.Listbox(buy_window, font=("Arial", 12), selectmode=tk.SINGLE)
    for item in items:
        item_listbox.insert(tk.END, f"{item['name']} - Vendido por: {item['seller']} - Precio: ${item['price']:.2f}")
    item_listbox.pack(pady=10)

    def confirm_purchase():
        selected_item_index = item_listbox.curselection()
        if not selected_item_index:
            messagebox.showerror("Error", "Seleccione un objeto para comprar.")
            return

        # Eliminar el objeto seleccionado del archivo JSON
        item_index = selected_item_index[0]
        purchased_item = items.pop(item_index)

        with open('items.json', 'w', encoding='utf-8') as file:
            json.dump(items, file, indent=4)

        messagebox.showinfo("Éxito", f"Has comprado {purchased_item['name']}.")

        buy_window.destroy()

    confirm_button = ttk.Button(buy_window, text="Confirmar compra", command=confirm_purchase)
    confirm_button.pack(pady=20)


def sell_item(username):
    def publish_item():
        item_name = item_entry.get()
        item_price = price_entry.get()

        if not item_name or not item_price:
            messagebox.showerror("Error",
                                 "Por favor, introduzca el nombre y el precio del objeto.")
            return

        try:
            price = float(
                item_price)  # Asegúrate de que el precio sea un número
        except ValueError:
            messagebox.showerror("Error", "El precio debe ser un número.")
            return

        # Añadir el nuevo objeto al archivo items.json
        if os.path.exists('items.json'):
            with open('items.json', 'r', encoding='utf-8') as file:
                try:
                    items = list(json.load(file))
                except json.JSONDecodeError:
                    items = []
        else:
            items = []

        new_item = {
            'name': item_name,
            'seller': username,
            'price': price
        }
        items.append(new_item)

        with open('items.json', 'w', encoding='utf-8') as file:
            json.dump(items, file, indent=4)

        messagebox.showinfo("Éxito",
                            f"El objeto '{item_name}' ha sido publicado por {username} por ${price:.2f}.")
        sell_window.destroy()

    # Ventana para vender
    sell_window = tk.Toplevel()
    sell_window.title("Vender objeto")
    sell_window.geometry("300x250")
    sell_window.configure(bg='#f0f0f0')

    sell_label = tk.Label(sell_window, text="Ingrese el nombre del objeto:",
                          bg='#f0f0f0', font=("Arial", 12))
    sell_label.pack(pady=10)

    item_entry = tk.Entry(sell_window, font=("Arial", 12))
    item_entry.pack(pady=5)

    price_label = tk.Label(sell_window, text="Ingrese el precio del objeto:",
                           bg='#f0f0f0', font=("Arial", 12))
    price_label.pack(pady=10)

    price_entry = tk.Entry(sell_window, font=("Arial", 12))
    price_entry.pack(pady=5)

    sell_button = ttk.Button(sell_window, text="Publicar",
                             command=publish_item)
    sell_button.pack(pady=20)


# Interfaz gráfica de login
root = tk.Tk()
root.title("Registro e Inicio de Sesión")
root.configure(bg='#f0f0f0')
root.geometry("400x300")

# Estilos de ttk
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=6, relief="flat",
                background="#5a9")
style.map("TButton", background=[("active", "#479")])

# Etiqueta de bienvenida
welcome_label = tk.Label(root, text="Bienvenido al programa", bg='#f0f0f0',
                         font=("Arial", 16, "bold"))
welcome_label.pack(pady=10)

# Etiqueta de instrucciones
option_label = tk.Label(root, text="Seleccione una opción:", bg='#f0f0f0',
                        font=("Arial", 12))
option_label.pack(pady=5)

# Crear un Frame para los botones
button_frame = tk.Frame(root, bg='#f0f0f0')
button_frame.pack(pady=10)

# Botón de registro
register_button = ttk.Button(button_frame, text="Registrarse",
                             command=register)
register_button.grid(row=0, column=0, padx=10)

# Botón de iniciar sesión
login_button = ttk.Button(button_frame, text="Iniciar sesión", command=login)
login_button.grid(row=0, column=1, padx=10)

# Etiqueta y campo de entrada para el nombre de usuario
username_label = tk.Label(root, text="Nombre de usuario", bg='#f0f0f0',
                          font=("Arial", 12))
username_label.pack(pady=5)

username_entry = tk.Entry(root, font=("Arial", 12))
username_entry.pack(pady=5)

# Etiqueta y campo de entrada para la contraseña
password_label = tk.Label(root, text="Contraseña", bg='#f0f0f0',
                          font=("Arial", 12))
password_label.pack(pady=5)

password_entry = tk.Entry(root, show="*", font=("Arial", 12))
password_entry.pack(pady=5)

root.mainloop()

