from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

app = Flask(__name__)
app.secret_key = 'no_se_por_que_hay_que_definir_una_clave'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'basededatos/database.db')
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    nombre = db.Column(db.String(80), nullable=False)
    ciudad = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    key = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.String(120), nullable=False)
    updated_at = db.Column(db.String(120), nullable=False)
    objetos_vendidos = db.Column(db.String(200), nullable=True, default="")
    objetos_comprados = db.Column(db.String(200), nullable=True, default="")
    products_sold = db.relationship('Product', backref='seller', lazy=True, foreign_keys='Product.seller_id')
    products_bought = db.relationship('Product', backref='buyer', lazy=True, foreign_keys='Product.buyer_id')

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='en venta')
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.String(120), nullable=False)


class Friend(db.Model):
    __tablename__ = 'friends'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    befriended_at = db.Column(db.String(120), nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])
    friend = db.relationship('User', foreign_keys=[friend_id])


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode()  # La contraseña debe ser bytes
        nombre = request.form['nombre']
        ciudad = request.form['ciudad']
        email = request.form['email']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        key = kdf.derive(password)

        user = User(username=username, nombre=nombre, ciudad=ciudad, email=email, key=key.hex(), salt=salt.hex(), created_at=now, updated_at=now)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode()  # La contraseña debe ser bytes
        user = User.query.filter_by(username=username).first()
        if user:
            salt = bytes.fromhex(user.salt)
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
            key = kdf.derive(password)
            if key.hex() == user.key:
                session['user_id'] = user.id  # Almacena el ID del usuario en la sesión
                return redirect(url_for('app_route'))
            else:
                return "Contraseña incorrecta, por favor intenta de nuevo."
        else:
            return "Usuario no encontrado, por favor regístrate."
    return render_template('login.html')

@app.route('/app_route')
def app_route():
    return render_template('app.html')

@app.route('/comprar', methods=['GET', 'POST'])
def comprar():
    if request.method == 'POST':
        product_id = request.form['product_id']
        buyer_id = session.get('user_id')  # Obtiene el ID del usuario actual

        product = Product.query.get(product_id)
        product.status = 'vendido'
        product.buyer_id = buyer_id
        db.session.commit()

        buyer = User.query.get(buyer_id)
        buyer.objetos_comprados += f"{product.id},"
        db.session.commit()

        return redirect(url_for('comprar'))

    products = Product.query.filter_by(status='en venta').all()
    return render_template('comprar.html', products=products)

@app.route('/vender', methods=['GET', 'POST'])
def vender():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        price = float(request.form['price'])
        description = request.form['description']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        seller_id = session.get('user_id')

        product = Product(name=name, category=category, price=price, description=description, created_at=now, seller_id=seller_id)
        db.session.add(product)
        db.session.commit()

        user = User.query.get(seller_id)
        user.objetos_vendidos += f"{product.id},"
        db.session.commit()

        return "Producto publicado exitosamente."
    return render_template('vender.html')

@app.route('/perfil')
def perfil():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    return render_template('perfil.html', user=user)

@app.route('/amigos')
def amigos():
    return render_template('amigos.html')

@app.route('/productos')
def productos():
    return render_template('productos.html')

@app.route('/carrito')
def carrito():
    return render_template('carrito.html')


if __name__ == '__main__':
    app.run(debug=True)