-- Eliminar tablas si existen
-- DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS items;

-- Crear tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    nombre TEXT NOT NULL,
    ciudad TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    key TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Crear tabla de artículos
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    seller_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (seller_id) REFERENCES users(id)
);

-- Insertar datos de ejemplo
INSERT INTO users (username, nombre, ciudad, email, key, salt, created_at, updated_at)
VALUES ('johndoe', 'John Doe', 'New York', 'johndoe@example.com', 'somekey', 'somesalt', '2023-10-01', '2023-10-01');

INSERT INTO items (name, description, price, seller_id, created_at, updated_at)
VALUES ('Laptop', 'A powerful laptop', 999.99, 1, '2023-10-01', '2023-10-01');

-- Realizar un SELECT para ver los datos
SELECT * FROM users;
SELECT * FROM items;