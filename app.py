import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from json_handler import JsonHandler
import os

class App:
    def __init__(self, root):
        self.root = root
        self.json_handler = JsonHandler()
        self.setup_ui()

    def setup_ui(self):
        # Estilos de ttk
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=6,
                        relief="flat",
                        background="#5a9")
        style.map("TButton", background=[("active", "#479")])

        # Etiqueta de bienvenida
        welcome_label = tk.Label(self.root, text="Bienvenido a WallaPop",
                                 bg='#f0f0f0',
                                 font=("Arial", 16, "bold"))
        welcome_label.pack(pady=10)

        # Etiqueta de instrucciones
        option_label = tk.Label(self.root, text="Seleccione una opción:",
                                bg='#f0f0f0',
                                font=("Arial", 12))
        option_label.pack(pady=5)

        # Crear un Frame para los botones
        button_frame = tk.Frame(self.root, bg='#f0f0f0')
        button_frame.pack(pady=10)

        # Botón de registro
        register_button = ttk.Button(button_frame, text="Registrarse",
                                     command=self.register)
        register_button.grid(row=0, column=0, padx=10)

        # Enlace para iniciar sesión
        login_link = tk.Label(button_frame, text="¿Ya tienes una cuenta? Inicia sesión aquí",
                              bg='#f0f0f0',
                              font=("Arial", 12), fg="blue", cursor="hand2")
        login_link.grid(row=1, column=0, padx=10)
        login_link.bind("<Button-1>", self.login)

        # Etiqueta y campo de entrada para el nombre de usuario
        username_label = tk.Label(self.root, text="Nombre de usuario",
                                  bg='#f0f0f0',
                                  font=("Arial", 12))
        username_label.pack(pady=5)

        self.username_entry = tk.Entry(self.root, font=("Arial", 12))
        self.username_entry.pack(pady=5)

        # Etiqueta y campo de entrada para la contraseña
        password_label = tk.Label(self.root, text="Contraseña", bg='#f0f0f0',
                                  font=("Arial", 12))
        password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.root, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)

    def login(self, event=None):
        # Crear nueva ventana de inicio de sesión
        login_window = tk.Toplevel(self.root)
        login_window.title("Iniciar sesión")
        login_window.geometry("400x400")
        login_window.configure(bg='#f0f0f0')

        # Enlace para registrarse
        register_link = tk.Label(login_window, text="¿No tienes una cuenta? Regístrate aquí",
                                 bg='#f0f0f0',
                                 font=("Arial", 12), fg="blue", cursor="hand2")
        register_link.pack(pady=10)
        register_link.bind("<Button-1>", self.register)

        # Etiqueta y campo de entrada para el nombre de usuario
        username_label = tk.Label(login_window, text="Nombre de usuario",
                                  bg='#f0f0f0',
                                  font=("Arial", 12))
        username_label.pack(pady=5)

        self.username_entry = tk.Entry(login_window, font=("Arial", 12))
        self.username_entry.pack(pady=5)

        # Etiqueta y campo de entrada para la contraseña
        password_label = tk.Label(login_window, text="Contraseña", bg='#f0f0f0',
                                  font=("Arial", 12))
        password_label.pack(pady=5)

        self.password_entry = tk.Entry(login_window, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)

        # Botón de iniciar sesión
        login_button = ttk.Button(login_window, text="Iniciar sesión",
                                  command=self.login_action)
        login_button.pack(pady=10)

    def register(self, event=None):
        # Crear nueva ventana de registro
        register_window = tk.Toplevel(self.root)
        register_window.title("Registrarse")
        register_window.geometry("400x400")
        register_window.configure(bg='#f0f0f0')

        # Enlace para iniciar sesión
        login_link = tk.Label(register_window, text="¿Ya tienes una cuenta? Inicia sesión aquí",
                              bg='#f0f0f0',
                              font=("Arial", 12), fg="blue", cursor="hand2")
        login_link.pack(pady=10)
        login_link.bind("<Button-1>", self.login)

        # Etiqueta y campo de entrada para el nombre de usuario
        username_label = tk.Label(register_window, text="Nombre de usuario",
                                  bg='#f0f0f0',
                                  font=("Arial", 12))
        username_label.pack(pady=5)

        self.username_entry = tk.Entry(register_window, font=("Arial", 12))
        self.username_entry.pack(pady=5)

        # Etiqueta y campo de entrada para la contraseña
        password_label = tk.Label(register_window, text="Contraseña", bg='#f0f0f0',
                                  font=("Arial", 12))
        password_label.pack(pady=5)

        self.password_entry = tk.Entry(register_window, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)

        # Botón de registro
        register_button = ttk.Button(register_window, text="Registrarse",
                                     command=self.register_action)
        register_button.pack(pady=10)

    def login_action(self):
        username = self.username_entry.get()
        password = self.password_entry.get().encode()

        if not username or not password:
            messagebox.showerror("Error",
                                 "Por favor, rellene todos los campos.")
            return

        if os.path.exists('json_files/users.json'):
            existing_data = self.json_handler.read_json('users.json')

            for user in existing_data:
                if user['username'] == username:
                    salt = bytes.fromhex(user['salt'])
                    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
                    try:
                        kdf.verify(password, bytes.fromhex(user['key']))
                        self.open_success_window(
                            username)  # Abrir la ventana de éxito
                        return
                    except:
                        messagebox.showerror("Error", "Contraseña incorrecta.")
                        return
            messagebox.showerror("Error", "Nombre de usuario no encontrado.")
        else:
            messagebox.showerror("Error",
                                 "No hay usuarios registrados. Regístrese primero.")

    def register_action(self):
        username = self.username_entry.get()
        password = self.password_entry.get().encode()

        if not username or not password:
            messagebox.showerror("Error",
                                 "Por favor, rellene todos los campos.")
            return

        # Comprobar si el nombre de usuario ya existe
        if os.path.exists('json_files/users.json'):
            existing_data = self.json_handler.read_json('users.json')
            for user in existing_data:
                if user['username'] == username:
                    messagebox.showerror("Error",
                                         "El nombre de usuario ya existe.")
                    return
        else:
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

        self.json_handler.write_json('users.json', existing_data)

        messagebox.showinfo("Éxito", "Registro exitoso.")

    def open_success_window(self, username):
        # Cerrar la ventana de login
        self.root.destroy()

        # Crear nueva ventana
        success_window = tk.Tk()
        success_window.title("Inicio de sesión exitoso")
        success_window.geometry("400x400")
        success_window.configure(bg='#f0f0f0')

        # Mensaje de éxito
        success_label = tk.Label(success_window,
                                 text=f"¡Bienvenido de nuevo, {username}!",
                                 font=("Arial", 16, "bold"), bg='#f0f0f0')
        success_label.pack(pady=20)

        # Botones para Comprar y Vender
        buy_button = ttk.Button(success_window, text="Comprar objeto", command=lambda: self.buy_item(username))
        buy_button.pack(pady=10)

        sell_button = ttk.Button(success_window, text="Vender objeto", command=lambda: self.sell_item(username))
        sell_button.pack(pady=10)

        success_window.mainloop()

    def buy_item(self, username):
        items = self.json_handler.read_json('items.json')

        if not items:
            messagebox.showinfo("Información", "No hay objetos disponibles.")
            return

        # Ventana para comprar
        buy_window = tk.Toplevel()
        buy_window.title("Comprar objeto")
        buy_window.geometry("400x300")
        buy_window.configure(bg='#f0f0f0')

        buy_label = tk.Label(buy_window,
                             text="Seleccione un objeto para comprar:",
                             bg='#f0f0f0', font=("Arial", 12))
        buy_label.pack(pady=10)

        # Crear Treeview
        columns = ("Nombre", "Vendedor", "Precio")
        item_tree = ttk.Treeview(buy_window, columns=columns, show='headings',
                                 height=8)

        # Configurar las columnas
        item_tree.heading("Nombre", text="Nombre")
        item_tree.heading("Vendedor", text="Vendedor")
        item_tree.heading("Precio", text="Precio")

        for item in items:
            item_tree.insert("", tk.END, values=(
                item['name'], item['seller'], f"${item['price']:.2f}"))

        item_tree.pack(pady=10)

        def confirm_purchase():
            selected_item_index = item_tree.selection()
            if not selected_item_index:
                messagebox.showerror("Error",
                                     "Seleccione un objeto para comprar.")
                return

            # Obtener el objeto seleccionado y eliminarlo
            item_index = item_tree.index(selected_item_index[0])
            purchased_item = items.pop(item_index)

            with open('json_files/items.json', 'w', encoding='utf-8') as file:
                self.json_handler.write_json('items.json', items)

            messagebox.showinfo("Éxito",
                                f"Has comprado {purchased_item['name']} por {purchased_item['price']:.2f}.")
            buy_window.destroy()

        confirm_button = ttk.Button(buy_window, text="Confirmar compra",
                                    command=confirm_purchase)
        confirm_button.pack(pady=20)

        style = ttk.Style()
        style.configure("Treeview", font=("Arial", 12), rowheight=30)
        style.configure("Treeview.Heading", font=("Arial", 14, "bold"))

    def sell_item(self, username):
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
            items = self.json_handler.read_json('items.json')

            new_item = {
                'name': item_name,
                'seller': username,
                'price': price
            }
            items.append(new_item)

            self.json_handler.write_json('items.json', items)

            messagebox.showinfo("Éxito",
                                f"El objeto '{item_name}' ha sido publicado por {username} por ${price:.2f}.")
            sell_window.destroy()

        # Ventana para vender
        sell_window = tk.Toplevel()
        sell_window.title("Vender objeto")
        sell_window.geometry("300x250")
        sell_window.configure(bg='#f0f0f0')

        sell_label = tk.Label(sell_window,
                              text="Ingrese el nombre del objeto:",
                              bg='#f0f0f0', font=("Arial", 12))
        sell_label.pack(pady=10)

        item_entry = tk.Entry(sell_window, font=("Arial", 12))
        item_entry.pack(pady=5)

        price_label = tk.Label(sell_window,
                               text="Ingrese el precio del objeto:",
                               bg='#f0f0f0', font=("Arial", 12))
        price_label.pack(pady=10)

        price_entry = tk.Entry(sell_window, font=("Arial", 12))
        price_entry.pack(pady=5)

        sell_button = ttk.Button(sell_window, text="Publicar",
                                 command=publish_item)
        sell_button.pack(pady=20)