-- Eliminar tablas si existen
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

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
    updated_at TEXT NOT NULL,
    objetos_vendidos TEXT DEFAULT '',
    objetos_comprados TEXT DEFAULT ''
);

-- Crear tabla de productos
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'en venta',
    seller_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (seller_id) REFERENCES users(id)
);