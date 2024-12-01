
-- Crear la tabla Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    nombre TEXT NOT NULL,
    ciudad TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    bank_account TEXT NOT NULL DEFAULT '',
    key TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    objetos_vendidos TEXT DEFAULT '',
    objetos_comprados TEXT DEFAULT ''
);

-- Crear la tabla UserKeys
CREATE TABLE IF NOT EXISTS user_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    certificate TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Crear la tabla Products
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'en venta',
    seller_id INTEGER NOT NULL,
    buyer_id INTEGER,
    message TEXT,
    created_at TEXT NOT NULL,
    signature TEXT,
    FOREIGN KEY (seller_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES users (id) ON DELETE SET NULL
);

-- Crear la tabla Friends
CREATE TABLE IF NOT EXISTS friends (
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    befriended_at TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users (id) ON DELETE CASCADE
);
