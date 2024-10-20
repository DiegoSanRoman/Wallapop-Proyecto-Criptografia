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

def generate_hmac(secret_key, message):
    """Genera un HMAC usando SHA256"""
    hmac_obj = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256)
    return base64.b64encode(hmac_obj.digest()).decode()

def validate_hmac(secret_key, message, received_hmac):
    """Valida el HMAC recibido"""
    generated_hmac = generate_hmac(secret_key, message)
    return hmac.compare_digest(generated_hmac, received_hmac)


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

"""
class Offer(db.Model):
    __tablename__ = 'offers'
    id = db.Column(db.Integer, primary_key=True)
    product = 
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    hmac_message = 
"""

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
        key = derive_key(password, salt)

        user = User(username=username, nombre=nombre, ciudad=ciudad, email=email, key=key.hex(), salt=salt.hex(), created_at=now, updated_at=now)
        db.session.add(user)
        db.session.commit()
        #return redirect(url_for('login'))
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
                send_token_via_email(user.email, token)

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
            return redirect(url_for('app_route'))  # Redirige a la ruta principal de la aplicación

        return redirect(url_for('app_route'))
    return render_template('continue.html')


@app.route('/app_route')
def app_route():
    return render_template('app.html')

"""
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
"""
"""
Quiero que a la hora de comprar un producto no se compre directamente. Sino que salte una solicitud al vendedor y 
que el vendedor lo tenga que aceptar (para usar la autenticación de mensajes más que nada).
"""
@app.route('/comprar', methods=['GET', 'POST'])
def comprar():
    if request.method == 'POST':
        product_id = request.form['product_id']
        buyer_id = session.get('user_id')  # Obtiene el ID del usuario actual

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

    products = Product.query.filter_by(status='en venta').all()
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
    return render_template('productos.html')

@app.route('/carrito')
def carrito():
    return render_template('carrito.html')

def derive_key(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    key = kdf.derive(password)
    return key

# Para generar el token para enviar el correo de verificación
def generate_token():
    """Genera un token de 6 dígitos"""
    return str(random.randint(100000, 999999))

def send_token_via_email(user_email, token):
    """Envía el token al correo del usuario"""
    msg = Message('Tu código de verificación', recipients=[user_email])
    msg.body = f'Tu código de verificación es: {token}'
    mail.send(msg)

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_GCM)  # Modo GCM
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    # Almacenar el IV (nonce), el texto cifrado y el tag para la verificación
    return (
        base64.b64encode(cipher.nonce).decode(),
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(tag).decode()
    )

"""
# Para dividir la cadena en tres partes utilizando el delimitador ":"
nonce, encrypted_bank_acc, tag = data.split(":")
"""

def decrypt_data(nonce, ciphertext, tag, key):
    nonce = base64.b64decode(nonce.encode())
    ciphertext = base64.b64decode(ciphertext.encode())
    tag = base64.b64decode(tag.encode())

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data.decode()


if __name__ == '__main__':
    app.run(debug=True)