from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask_mail import Mail
from Criptografia import derive_key, validar_fortaleza, encrypt_data, decrypt_data, generate_token, send_token_via_email

# Crear la aplicación de Flask
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

# Definir las tablas de la base de datos
# Tabla de usuarios
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

# Tabla de productos
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
    message = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.String(120), nullable=False)

# Tabla de amigos
class Friend(db.Model):
    __tablename__ = 'friends'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    befriended_at = db.Column(db.String(120), nullable=False)
    user = db.relationship('User', foreign_keys=[user_id])
    friend = db.relationship('User', foreign_keys=[friend_id])

# Crear las tablas en la base de datos
with app.app_context():
    db.create_all()

# Rutas de la aplicación
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Si el usuario ya está autenticado, redirigir a la página principal
    if request.method == 'POST':
        # Obtener los datos del formulario
        username = request.form['username']
        password = request.form['password']  # La contraseña debe ser un string, no es necesario `.encode()` todavía
        nombre = request.form['nombre']
        ciudad = request.form['ciudad']
        email = request.form['email']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Verificar si el username ya está registrado
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "El nombre de usuario ya está registrado. Por favor, escoja otro."

        # Verificar si el correo electrónico ya está registrado
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return "El correo electrónico ya está en uso. Por favor, introduzca otro."

        # Validar la robustez de la contraseña
        is_valid, error_message = validar_fortaleza(password)
        if not is_valid:
            return error_message  # Mostrar el mensaje de error

        # Derivar la clave a partir de la contraseña y una salt aleatoria
        password = password.encode()        # Convertir la contraseña a bytes para usarla con el KDF
        salt = os.urandom(16)               # Generar una salt aleatoria
        key = derive_key(password, salt)    # Derivar la clave a partir de la contraseña y la salt

        # Convertir la salt y la clave a hexadecimal para almacenarlas en la base de datos
        user = User(username=username, nombre=nombre, ciudad=ciudad, email=email, key=key.hex(), salt=salt.hex(), created_at=now, updated_at=now)
        # Guardar el usuario en la base de datos
        db.session.add(user)
        db.session.commit()

        # Iniciar sesión automáticamente después de registrarse
        session['user_id'] = user.id
        return redirect(url_for('continue_info'))

    return render_template('register.html')

@app.route('/continue', methods=['GET', 'POST'])
def continue_info():
    # Si el usuario no está autenticado, redirigir a la página de inicio de sesión
    if request.method == 'POST':
        # Obtener el número de cuenta bancaria
        bank_acc = request.form['bank-acc']
        print(f'Número de cuenta recibido: {bank_acc}')

        # Obtener el usuario actual
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        print(f"user_id: {user_id}")

        # Cifrar el número de cuenta bancaria y guardarlo en la base de datos si el usuario existe
        if user:
            # Usar la clave derivada del usuario para cifrar
            key = bytes.fromhex(user.key)

            # Cifrar el número de cuenta
            user.bank_account = encrypt_data(bank_acc, key)
            db.session.commit()

            # Datos sobre el cifrado
            algorithm = 'AES-GCM'
            key_length = 256  # bits

            # Mostrar la página con el popup
            return render_template('popup.html', algorithm=algorithm, key_length=key_length, account_number=bank_acc)

        return redirect(url_for('app_route'))  # Redirige si no hay usuario

    return render_template('continue.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya está autenticado, redirigir a la página principal
    if request.method == 'POST':
        # Obtener los datos del formulario
        username = request.form['username']
        password = request.form['password'].encode()  # La contraseña debe ser bytes
        user = User.query.filter_by(username=username).first()
        # Verificar si el usuario existe
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
    # Si el usuario no está autenticado, redirigir a la página de inicio de sesión
    if request.method == 'POST':
        # Verificar el token ingresado por el usuario
        entered_token = request.form['token']
        if entered_token == session.get('2fa_token'):
            # Si el token es correcto, el usuario está autenticado
            session.pop('2fa_token', None)  # Eliminar el token de la sesión
            return redirect(url_for('app_route'))
        else:
            return "Código de verificación incorrecto, por favor intenta de nuevo." # Mensaje de error
    return render_template('verify_2fa.html')

@app.route('/app_route')
def app_route():
    return render_template('app.html')

@app.route('/comprar', methods=['GET', 'POST'])
def comprar():
    # Obtener el ID del comprador
    buyer_id = session.get('user_id')

    # Si el usuario no está autenticado, redirigir a la página de inicio de sesión
    if request.method == 'POST':
        # Obtener el ID del producto y el vendedor
        product_id = request.form['product_id']
        product = Product.query.get(product_id)
        seller = User.query.get(product.seller_id)

        # Obtener la información del comprador
        buyer = User.query.get(buyer_id)
        key = bytes.fromhex(buyer.key)
        bank_account = decrypt_data(buyer.bank_account, key)

        # Datos sobre el cifrado
        algorithm = 'AES-GCM'
        key_length = 256  # bits

        # Redirigir a 'comprando.html' con detalles del producto y la información adicional
        return render_template('comprando.html', product=product, seller=seller, bank_account=bank_account, algorithm=algorithm, key_length=key_length)

    products = Product.query.filter_by(status='en venta').filter(Product.seller_id != buyer_id).all()
    return render_template('comprar.html', products=products)


@app.route('/solicitar_compra', methods=['POST'])
def solicitar_compra():
    # Obtener el producto y actualizar su estado
    product_id = request.form['product_id']
    product = Product.query.get(product_id)
    product.status = 'pendiente de confirmación'

    # Asignar el buyer_id del producto al usuario actual
    buyer_id = session.get('user_id')
    product.buyer_id = buyer_id

    # Obtener la clave del comprador para cifrar el mensaje
    buyer = User.query.get(buyer_id)

    # Obtener el mensaje del formulario y cifrarlo
    message = request.form['message']
    secret_key = bytes.fromhex(buyer.key)  # Convertir clave de hexadecimal a bytes

    # Cifrar el mensaje
    encrypted_message = encrypt_data(message, secret_key)

    # Guardar el mensaje cifrado en la base de datos
    product.message = encrypted_message
    db.session.commit()

    # Redirigir al flujo de compra
    return redirect(url_for('comprar', product=product, original_message=message, buyer=buyer))


@app.route('/validar_compra', methods=['POST'])
def validar_compra():
    # Validar la compra y marcar el producto como vendido
    try:
        # Obtener el ID del producto y del comprador
        product_id = request.form['product_id']
        buyer_id = request.form['buyer_id']
        print(f"validar_compra - product_id: {product_id}, buyer_id: {buyer_id}")

        # Obtén el producto
        product = Product.query.get(product_id)
        if not product:
            print("validar_compra - Producto no encontrado.")
            return "Error: Producto no encontrado.", 404

        print(f"validar_compra - Producto encontrado. ID vendedor: {product.seller_id}")

        # Obtén la clave del vendedor para desencriptar
        buyer = User.query.get(product.buyer_id)
        if not buyer:
            print("validar_compra - Vendedor no encontrado.")
            return "Error: Vendedor no encontrado.", 404

        secret_key = bytes.fromhex(buyer.key)
        print(f"validar_compra - Clave secreta del vendedor obtenida: {secret_key.hex()}")

        # Separar el mensaje cifrado en nonce, ciphertext y tag
        try:
            nonce, ciphertext, tag = product.message.split(':')
            print(f"validar_compra - Nonce recuperado: {nonce}")
            print(f"validar_compra - Ciphertext recuperado: {ciphertext}")
            print(f"validar_compra - Tag recuperado: {tag}")
        except Exception as split_error:
            print(f"validar_compra - Error al separar mensaje cifrado: {split_error}")
            return "Error al procesar los datos cifrados", 400

        # Desencriptar usando AES-GCM. Si el tag es incorrecto, fallará.
        original_message = decrypt_data(product.message, secret_key)
        print(f"validar_compra - Mensaje desencriptado exitosamente: {original_message}")

        # Si la desencriptación es exitosa, marca el producto como vendido
        product.status = 'vendido'
        product.buyer_id = buyer_id
        db.session.commit()
        print("validar_compra - Estado del producto actualizado a 'vendido'.")

        # Actualiza el historial de compras del comprador
        buyer = User.query.get(buyer_id)
        if not buyer:
            print("validar_compra - Comprador no encontrado.")
            return "Error: Comprador no encontrado.", 404

        buyer.objetos_comprados += f"{product.id},"
        db.session.commit()
        print(f"validar_compra - Historial de compras del comprador actualizado: {buyer.objetos_comprados}")

        #return f"Compra validada exitosamente. Mensaje del comprador: {original_message}"
        return redirect(url_for('productos'))

    except Exception as e:
        print(f"validar_compra - Error durante la validación: {e}")
        return "Error: la autenticación falló.", 403


@app.route('/rechazar_compra', methods=['POST'])
def rechazar_compra():
    # Rechazar la compra y restablecer el estado del producto
    product_id = request.form['product_id']

    # Obtener el producto y restablecer su estado y comprador
    product = Product.query.get(product_id)
    product.buyer_id = None  # Restablecer el buyer_id a null
    product.status = 'en venta'  # Cambiar el estado del producto a 'en venta'

    # Guardar los cambios en la base de datos
    db.session.commit()

    return redirect(url_for('productos'))

@app.route('/vender', methods=['GET', 'POST'])
def vender():
    # Si el usuario no está autenticado, redirigir a la página de inicio de sesión
    if request.method == 'POST':
        # Obtener los datos del formulario
        name = request.form['name']
        category = request.form['category']
        price = float(request.form['price'])
        description = request.form['description']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        seller_id = session.get('user_id')

        # Crear un nuevo producto y guardarlo en la base de datos
        product = Product(name=name, category=category, price=price, description=description, created_at=now, seller_id=seller_id)
        db.session.add(product)
        db.session.commit()

        # Actualizar el historial de productos vendidos del vendedor
        user = User.query.get(seller_id)
        user.objetos_vendidos += f"{product.id},"
        db.session.commit()

        return "Producto publicado exitosamente."
    return render_template('vender.html')

@app.route('/perfil')
def perfil():
    # Si el usuario no está autenticado, redirigir a la página de inicio de sesión
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Obtener el usuario actual
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

    # Obtener productos vendidos, en venta y pendientes de confirmación para el vendedor actual
    productos_pendientes = Product.query.filter_by(seller_id=user_id, status='pendiente de confirmación').all()
    productos_en_venta = Product.query.filter_by(seller_id=user_id, status='en venta').all()
    productos_vendidos = Product.query.filter_by(seller_id=user_id, status='vendido').all()

    return render_template('productos.html',
                           productos_pendientes=productos_pendientes,
                           productos_en_venta=productos_en_venta,
                           productos_vendidos=productos_vendidos)

@app.route('/carrito')
def carrito():
    return render_template('carrito.html')


@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    try:
        product_id = request.form.get('product_id')
        product = Product.query.get(product_id)
        # Aquí deberías obtener el mensaje cifrado asociado al product_id desde la base de datos.
        encrypted_message = product.message

        # Obtenemos la secret_key
        buyer = User.query.get(product.buyer_id)
        secret_key = bytes.fromhex(buyer.key)
        # Usar la función decrypt_data que ya has definido
        decrypted_message = decrypt_data(encrypted_message, secret_key)

        return jsonify({'message': decrypted_message})

    except Exception as e:
        print(f'Error during decryption: {str(e)}')
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)