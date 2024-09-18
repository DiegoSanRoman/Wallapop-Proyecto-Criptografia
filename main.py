import tkinter as tk
import json

def register():
    username = username_entry.get()
    password = password_entry.get()

    user_data = {
        'username': username,
        'password': password
    }

    with open('users.json', 'w') as file:
        json.dump(user_data, file)

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
