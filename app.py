from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hmac
import hashlib
from flask_mail import Mail, Message
import random
import re
from Criptografia import generate_hmac, validate_hmac, derive_key, validar_fortaleza, encrypt_data, decrypt_data, generate_token, send_token_via_email

app = Flask(__name__)
app.secret_key = 'no_se_por_que_hay_que_poner_una_clave'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'basededatos/database.db')
db = SQLAlchemy(app)

# Configuración para Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cryptowallapop@gmail.com'
app.config['MAIL_PASSWORD'] = 'xaai jdyr escm jvxj'
app.config['MAIL_DEFAULT_SENDER'] = 'cryptowallapop@gmail.com'

mail = Mail(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    nombre = db.Column(db.String(80), nullable=False)
    ciudad = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    bank_account = db.Column(db.String(50), nullable=False, default="")  # Usar cadena vacía como valor por defecto
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
        password = request.form['password']  # La contraseña debe ser un string, no es necesario `.encode()` todavía
        nombre = request.form['nombre']
        ciudad = request.form['ciudad']
        email = request.form['email']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Validar la robustez de la contraseña
        is_valid, error_message = validar_fortaleza(password)
        if not is_valid:
            return error_message  # Mostrar el mensaje de error

        password = password.encode()  # Convertir la contraseña a bytes para usarla con el KDF
        salt = os.urandom(16)
        key = derive_key(password, salt)

        user = User(username=username, nombre=nombre, ciudad=ciudad, email=email, key=key.hex(), salt=salt.hex(), created_at=now, updated_at=now)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        return redirect(url_for('continue_info'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode()  # La contraseña debe ser bytes
        user = User.query.filter_by(username=username).first()
        if user:
            # Derivar la clave del usuario y compararla con la clave derivada de la contraseña ingresada
            salt = bytes.fromhex(user.salt)
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
            key = kdf.derive(password)
            # Si las claves coinciden, el usuario está autenticado
            if key.hex() == user.key:
                # Generar el token 2FA y enviarlo al correo para realizar la verificación en dos pasos
                token = generate_token()
                session['2fa_token'] = token  # Guardar el token en la sesión
                session['user_id'] = user.id  # Guardar temporalmente el ID de usuario
                send_token_via_email(user.email, token, mail)

                # Redirigir a la página para ingresar el token de la verificación en dos pasos
                return redirect(url_for('verify_2fa'))
            else:
                return "Contraseña incorrecta, por favor intenta de nuevo."
        else:
            return "Usuario no encontrado, por favor regístrate."
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        entered_token = request.form['token']
        if entered_token == session.get('2fa_token'):
            # Si el token es correcto, el usuario está autenticado
            session.pop('2fa_token', None)  # Eliminar el token de la sesión
            return redirect(url_for('app_route'))
        else:
            return "Código de verificación incorrecto, por favor intenta de nuevo." # Mensaje de error
    return render_template('verify_2fa.html')

@app.route('/continue', methods=['GET', 'POST'])
def continue_info():
    if request.method == 'POST':
        bank_acc = request.form['bank-acc']
        print(f'Número de cuenta recibido: {bank_acc}')

        user_id = session.get('user_id')
        user = User.query.get(user_id)
        print(f"user_id: {user_id}")

        if user:
            # Usar la clave derivada del usuario para cifrar
            key = bytes.fromhex(user.key)

            # Cifrar el número de cuenta
            nonce, encrypted_bank_acc, tag = encrypt_data(bank_acc, key)
            print(f'Número de cuenta encriptado: {encrypted_bank_acc}')

            # Guardar el nonce, número de cuenta cifrado y tag (separado por ':')
            user.bank_account = f"{nonce}:{encrypted_bank_acc}:{tag}"
            db.session.commit()

            # Datos sobre el cifrado
            algorithm = 'AES-GCM'
            key_length = 256  # bits

            # Mostrar la página con el popup
            return render_template('popup.html', algorithm=algorithm, key_length=key_length, account_number=bank_acc)

        return redirect(url_for('app_route'))  # Redirige si no hay usuario

    return render_template('continue.html')

@app.route('/app_route')
def app_route():
    return render_template('app.html')

@app.route('/comprar', methods=['GET', 'POST'])
def comprar():
    buyer_id = session.get('user_id')  # Define buyer_id at the beginning of the function

    if request.method == 'POST':
        product_id = request.form['product_id']

        # Obtén el producto y su vendedor
        product = Product.query.get(product_id)
        seller = User.query.get(product.seller_id)

        # Genera un mensaje con la información clave para la transacción
        message = f"{product_id}:{buyer_id}"

        # Usa la clave secreta del vendedor para generar el HMAC
        secret_key = seller.key  # Usamos la clave secreta del vendedor
        hmac_message = generate_hmac(secret_key, message)

        # Simular el envío de la solicitud al vendedor con el HMAC
        # En una implementación real, esto podría ser un envío de correo o una notificación
        product.status = 'pendiente de confirmación'
        db.session.commit()
        offer = Offer(name=name, category=category, price=price, description=description, created_at=now,
                          seller_id=seller_id)
        db.session.add(product)
        db.session.commit()
        # send_request_to_seller(seller.email, product_id, buyer_id, hmac_message)

        # Guardamos temporalmente la solicitud o redirigimos al usuario a otra página
        # return redirect(url_for('confirmar_compra', product_id=product_id, hmac_message=hmac_message))

    products = Product.query.filter_by(status='en venta').filter(Product.seller_id != buyer_id).all()
    return render_template('comprar.html', products=products)

@app.route('/validar_compra', methods=['POST'])
def validar_compra():
    product_id = request.form['product_id']
    buyer_id = request.form['buyer_id']
    received_hmac = request.form['hmac_message']

    # Obtén el producto y el vendedor
    product = Product.query.get(product_id)
    seller = User.query.get(product.seller_id)

    # Genera el mensaje original y valida el HMAC recibido
    message = f"{product_id}:{buyer_id}"
    secret_key = seller.key  # Usamos la clave secreta del vendedor

    if validate_hmac(secret_key, message, received_hmac):
        # Si el HMAC es válido, marca el producto como vendido
        product.status = 'vendido'
        product.buyer_id = buyer_id
        db.session.commit()

        # Actualiza el historial de compras del comprador
        buyer = User.query.get(buyer_id)
        buyer.objetos_comprados += f"{product.id},"
        db.session.commit()

        return "Compra validada exitosamente."
    else:
        return "Error: la autenticación falló.", 403

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
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Recuperar todos los productos del usuario
    productos_en_venta = Product.query.filter_by(seller_id=user_id, status='en venta').all()
    productos_pendientes = Product.query.filter_by(seller_id=user_id, status='pendiente de confirmación').all()
    productos_vendidos = Product.query.filter_by(seller_id=user_id, status='vendido').all()

    return render_template('productos.html', productos_en_venta=productos_en_venta, productos_pendientes=productos_pendientes, productos_vendidos=productos_vendidos)

@app.route('/carrito')
def carrito():
    return render_template('carrito.html')

if __name__ == '__main__':
    app.run(debug=True)