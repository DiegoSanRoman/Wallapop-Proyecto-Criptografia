import sqlite3

# Conectar a la base de datos
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Leer el archivo SQL
with open('database.sql', 'r') as sql_file:
    sql_script = sql_file.read()

# Ejecutar el script SQL
cursor.executescript(sql_script)

# Confirmar los cambios
conn.commit()

# Cerrar la conexión
conn.close()