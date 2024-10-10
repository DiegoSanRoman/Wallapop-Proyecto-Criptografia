-- Eliminar tablas si existen
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS articulos;
DROP TABLE IF EXISTS users;
);

-- Crear tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    nombre TEXT NOT NULL,
    ciudad TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    bank_account NOT NULL,
    key TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    objetos_vendidos TEXT DEFAULT '',
    objetos_comprados TEXT DEFAULT ''
);

ALTER TABLE users ADD COLUMN bank_account TEXT NOT NULL DEFAULT '';

-- Crear tabla de productos
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'en venta',
    seller_id INTEGER NOT NULL,
    buyer_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (seller_id) REFERENCES users(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id)
);

-- Crear tabla de amigos
CREATE TABLE IF NOT EXISTS friends (
    id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    befriended_at DATE NOT NULL,
    PRIMARY KEY (user_id, friend_id),  -- Clave primaria compuesta
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE
