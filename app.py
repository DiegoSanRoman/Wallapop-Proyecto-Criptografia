from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.scrypt import InvalidKey
from cryptography.hazmat.primitives.asymmetric import rsa  # Para la generación de claves
from cryptography.hazmat.primitives import serialization  # Para la generación de claves
from cryptography.hazmat.primitives.asymmetric import padding  # Para la firma electrónica
from cryptography.hazmat.primitives import hashes  # Para la firma electrónica
from cryptography.exceptions import InvalidSignature
from flask_mail import Mail
from Criptografia import derive_key, validar_fortaleza, encrypt_data, decrypt_data, generate_token, send_token_via_email
from Certificados import create_csr, save_key_pair, create_ca, create_cert
import base64
from cryptography import x509


# Crear la aplicación de Flask
app = Flask(__name__)
app.secret_key = 'clave_secreta_aplicacion'  # Clave usada por Flask para manejar sesiones de usuario
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
    bank_account = db.Column(db.String(50), nullable=False, default="")
    key = db.Column(db.String(64), nullable=False)  # Definir la clave como una cadena hexadecimal de 64 caracteres
    salt = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.String(120), nullable=False)
    updated_at = db.Column(db.String(120), nullable=False)
    objetos_vendidos = db.Column(db.String(200), nullable=True, default="")
    objetos_comprados = db.Column(db.String(200), nullable=True, default="")
    products_sold = db.relationship('Product', backref='seller', lazy=True, foreign_keys='Product.seller_id')
    products_bought = db.relationship('Product', backref='buyer', lazy=True, foreign_keys='Product.buyer_id')
    keys = db.relationship('UserKeys', back_populates='user', uselist=False)

class UserKeys(db.Model):
    __tablename__ = 'user_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)  # Clave privada cifrada
    user = db.relationship('User', back_populates='keys')


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
    signature = db.Column(db.String(512), nullable=True)  # Firma digital

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
    #db.drop_all()
    db.create_all()

# Crear la autoridad certificadora (CA) si no existe
if not os.path.exists(os.path.join("Certificados", "ac1cert.pem")):
    create_ca()

# Rutas de la aplicación
@app.route('/')
def home():
    return render_template('home.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        nombre = request.form["nombre"]
        ciudad = request.form["ciudad"]
        email = request.form["email"]
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "El nombre de usuario ya está registrado."

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return "El correo electrónico ya está en uso."

        # Generar claves pública y privada
        private_key, public_key = save_key_pair(username)

        # Crear CSR
        csr_pem = create_csr(private_key, public_key, username)

        # Crear el certificado
        create_cert(csr_pem, username)

        # Generar una clave derivada de longitud adecuada para AES (256 bits)
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        key = kdf.derive(password.encode())

        # Convertir la clave derivada a hexadecimal
        key_hex = key.hex()

        # Crear el usuario
        user = User(
            username=username, nombre=nombre, ciudad=ciudad, email=email,
            key=key_hex,  # Almacenar la clave derivada como cadena hexadecimal
            salt=salt.hex(), created_at=now, updated_at=now
        )
        db.session.add(user)
        db.session.commit()

        # Guardar claves en la tabla UserKeys
        user_keys = UserKeys(
            user_id=user.id,
            public_key=public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            private_key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        )
        db.session.add(user_keys)
        db.session.commit()

        session['user_id'] = user.id
        return redirect(url_for("continue_info"))
    return render_template("register.html")

@app.route('/continue', methods=['GET', 'POST'])
def continue_info():
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
            nonce = os.urandom(12)  # Crear un nonce aleatorio
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            encrypted_bank_acc = encryptor.update(bank_acc.encode()) + encryptor.finalize()
            tag = encryptor.tag

            # Guardar el mensaje cifrado en la base de datos en formato 'nonce:ciphertext:tag'
            encrypted_message = f"{base64.b64encode(nonce).decode()}:{base64.b64encode(encrypted_bank_acc).decode()}:{base64.b64encode(tag).decode()}"
            user.bank_account = encrypted_message
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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode()  # La contraseña tiene que estar en bytes
        user = User.query.filter_by(username=username).first()
        if user:
            salt = bytes.fromhex(user.salt)
            try:
                # Derivar la clave a partir de la contraseña y la salt almacenada
                derived_key = derive_key(password, salt)
                # verificar la contraseña
                kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
                kdf.verify(password, bytes.fromhex(user.key))
                # Si la verificación es exitosa, enviar el código de verificación por correo
                token = generate_token()
                session['2fa_token'] = token  # Guardar el token en la sesión
                session['user_id'] = user.id  # Guardar el ID del usuario en la sesión
                send_token_via_email(user.email, token, mail)
                return redirect(url_for('verify_2fa'))
            except InvalidKey:
                return "Incorrect password, please try again."
        else:
            return "User not found, please register."
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


@app.route('/verificar_certificado_vendedor', methods=['POST'])
def verificar_certificado_vendedor():
    # Obtener el ID del vendedor del formulario
    seller_id = request.form['seller_id']
    seller = User.query.get(seller_id)
    if not seller:
        return jsonify({"status": "error", "message": "Vendedor no encontrado."}), 404

    # Cargar el certificado del vendedor
    cert_path = os.path.join("Certificados", "nuevoscerts", f"{seller.username}_cert.pem")
    if not os.path.exists(cert_path):
        return jsonify({"status": "error", "message": "Certificado no encontrado."}), 404

    try:
        # Intentar cargar el certificado
        with open(cert_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read())

        # Verificar la validez del certificado en términos de fecha
        current_time = datetime.utcnow()
        if cert.not_valid_before <= current_time <= cert.not_valid_after:
            return jsonify({"status": "success", "message": "Certificado válido."})
        else:
            return jsonify({"status": "error", "message": "Certificado expirado o no válido en este momento. Es peligroso continuar con la compra"})
    except Exception as e:
        # En caso de error al cargar el certificado
        return jsonify({"status": "error", "message": f"Certificado inválido: {str(e)}"})


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

        # Obtén la clave del comprador para desencriptar
        buyer = User.query.get(product.buyer_id)
        if not buyer:
            print("validar_compra - Vendedor no encontrado.")
            return "Error: Vendedor no encontrado.", 404

        secret_key = bytes.fromhex(buyer.key)
        print(f"validar_compra - Clave secreta del comprador obtenida: {secret_key}")


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
    if request.method == 'POST':
        # Obtener los datos del formulario
        name = request.form['name']
        category = request.form['category']
        price = float(request.form['price'])
        description = request.form['description']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        seller_id = session.get('user_id')

        # Recuperar la clave privada del usuario
        user_keys = UserKeys.query.filter_by(user_id=seller_id).first()
        if not user_keys:
            return "Error: No se encontraron claves asociadas al usuario.", 400
        print(f"Claves del usuario encontradas: {user_keys}")

        # Desencriptar la clave privada
        user = User.query.get(seller_id)

        # Convertir la clave de hexadecimal a bytes
        key = bytes.fromhex(user.key)

        # Obtener la clave privada cifrada desde la base de datos (ya en formato PEM)
        encrypted_private_key_pem = user_keys.private_key.strip()

        # No necesitamos decodificar ya que es un texto PEM. Cargamos la clave directamente.
        try:
            private_key = serialization.load_pem_private_key(
                encrypted_private_key_pem.encode('utf-8'),
                password=None,
            )
        except ValueError as e:
            return f"Error al cargar la clave privada: {str(e)}", 400

        # Crear una firma digital de los datos relevantes del producto
        product_data = f"{name}|{category}|{price}|{description}".encode()
        try:
            signature = private_key.sign(
                product_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            return f"Error al firmar los datos del producto: {str(e)}", 400

        # Crear un nuevo producto y guardarlo en la base de datos
        product = Product(
            name=name,
            category=category,
            price=price,
            description=description,
            created_at=now,
            seller_id=seller_id,
            signature=signature.hex()
        )

        db.session.add(product)
        db.session.commit()

        return redirect(url_for('app_route'))

    return render_template('vender.html')



@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    product_id = request.form['product_id']
    product = Product.query.get(product_id)
    seller = User.query.get(product.seller_id)
    user_keys = UserKeys.query.filter_by(user_id=seller.id).first()

    if not user_keys:
        return jsonify({"status": "error", "message": "No keys found for the user."}), 400

    public_key = serialization.load_pem_public_key(user_keys.public_key.encode())

    product_data = f"{product.name}|{product.category}|{product.price}|{product.description}".encode()
    signature = bytes.fromhex(product.signature)

    try:
        public_key.verify(
            signature,
            product_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({"status": "success", "message": f"Verification successful for product ID: {product_id}"})
    except InvalidSignature:
        return jsonify({"status": "error", "message": f"Verification failed for product ID: {product_id}"})

@app.route('/verificar_firma_producto', methods=['POST'])
def verificar_firma_producto():
    product_id = request.form['product_id']
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"status": "error", "message": "Producto no encontrado."}), 404

    seller = User.query.get(product.seller_id)
    user_keys = UserKeys.query.filter_by(user_id=seller.id).first()

    if not user_keys:
        return jsonify({"status": "error", "message": "No se encontraron claves públicas para el vendedor."}), 400

    public_key = serialization.load_pem_public_key(user_keys.public_key.encode())
    product_data = f"{product.name}|{product.category}|{product.price}|{product.description}".encode()
    signature = bytes.fromhex(product.signature)

    try:
        public_key.verify(
            signature,
            product_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({"status": "success", "message": "Firma del producto verificada correctamente."})
    except InvalidSignature:
        return jsonify({"status": "error", "message": "La firma del producto no es válida."})

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
    productos_comprados = Product.query.filter_by(buyer_id=user_id, status='vendido').all()

    return render_template('productos.html',
                           productos_pendientes=productos_pendientes,
                           productos_en_venta=productos_en_venta,
                           productos_vendidos=productos_vendidos, productos_comprados=productos_comprados)

@app.route('/carrito')
def carrito():
    user_id = session.get('user_id')

    # Obtener productos vendidos, en venta y pendientes de confirmación para el vendedor actual
    productos_carrito = Product.query.filter_by(buyer_id=user_id, status='pendiente de confirmación').all()

    return render_template('carrito.html', productos_carrito=productos_carrito)


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