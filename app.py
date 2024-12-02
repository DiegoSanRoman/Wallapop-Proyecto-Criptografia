from cryptography import x509                                                                                               # Para crear y manejar certificados X.509
from cryptography.hazmat._oid import NameOID                                                                                # Identificadores de nombres para atributos X.509
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms                                                # Para realizar cifrado simétrico
from flask import Flask, render_template, request, redirect, url_for, session, jsonify                                      # Importar herramientas para el desarrollo web con Flask
from flask_sqlalchemy import SQLAlchemy                                                                                     # Para trabajar con la base de datos usando SQLAlchemy
from datetime import datetime, timezone, timedelta                                                                          # Para manejar fechas y tiempos
import os                                                                                                                   # Para interactuar con el sistema operativo
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt                                                                # Función derivadora de claves Scrypt, para proteger contraseñas
from cryptography.hazmat.primitives.kdf.scrypt import InvalidKey                                                            # Para manejar excepciones en la verificación de claves
from cryptography.hazmat.primitives.asymmetric import rsa                                                                   # Para la generación de claves asimétricas RSA
from cryptography.hazmat.primitives import serialization                                                                    # Para serializar claves y otros objetos criptográficos
from cryptography.hazmat.primitives.asymmetric import padding                                                               # Para la firma electrónica con claves asimétricas
from cryptography.hazmat.primitives import hashes                                                                           # Para calcular hashes criptográficos
from cryptography.exceptions import InvalidSignature                                                                        # Para manejar excepciones relacionadas con firmas inválidas
from flask_mail import Mail                                                                                                 # Para enviar correos electrónicos usando Flask
from Criptografia import derive_key, validar_fortaleza, encrypt_data, decrypt_data, generate_token, send_token_via_email    # Funciones personalizadas de manejo criptográfico


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
    __tablename__ = 'users'  # Nombre de la tabla en la base de datos
    id = db.Column(db.Integer, primary_key=True)  # Identificador único de cada usuario (clave primaria)
    username = db.Column(db.String(80), unique=True, nullable=False)  # Nombre de usuario único y obligatorio
    nombre = db.Column(db.String(80), nullable=False)  # Nombre real del usuario, obligatorio
    ciudad = db.Column(db.String(80), nullable=False)  # Ciudad de residencia del usuario, obligatorio
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email único y obligatorio
    bank_account = db.Column(db.String(50), nullable=False, default="")  # Cuenta bancaria cifrada, opcional (vacía por defecto)
    key = db.Column(db.String(64), nullable=False)  # Clave de cifrado derivada, obligatoria
    salt = db.Column(db.String(32), nullable=False)  # Salt usado para derivar la clave de cifrado, obligatorio
    created_at = db.Column(db.String(120), nullable=False)  # Fecha de creación del usuario, obligatoria
    updated_at = db.Column(db.String(120), nullable=False)  # Fecha de última actualización del usuario, obligatoria
    objetos_vendidos = db.Column(db.String(200), nullable=True, default="")  # IDs de productos vendidos por el usuario (en formato texto)
    objetos_comprados = db.Column(db.String(200), nullable=True, default="")  # IDs de productos comprados por el usuario (en formato texto)
    products_sold = db.relationship('Product', backref='seller', lazy=True, foreign_keys='Product.seller_id')  # Relación uno a muchos con productos vendidos
    products_bought = db.relationship('Product', backref='buyer', lazy=True, foreign_keys='Product.buyer_id')  # Relación uno a muchos con productos comprados
    keys = db.relationship('UserKeys', back_populates='user', uselist=False)  # Relación uno a uno con la tabla UserKeys

# Tabla de claves y certificados del usuario
class UserKeys(db.Model):
    __tablename__ = 'user_keys'  # Nombre de la tabla en la base de datos
    id = db.Column(db.Integer, primary_key=True)  # Identificador único de cada registro (clave primaria)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Relación con la tabla User (clave foránea)
    public_key = db.Column(db.Text, nullable=False)  # Clave pública del usuario, obligatoria
    private_key = db.Column(db.Text, nullable=False)  # Clave privada cifrada del usuario, obligatoria
    certificate = db.Column(db.Text, nullable=False)  # Certificado X.509 del usuario, obligatorio
    user = db.relationship('User', back_populates='keys')  # Relación inversa con la tabla User

# Tabla de productos
class Product(db.Model):
    __tablename__ = 'products'  # Nombre de la tabla en la base de datos
    id = db.Column(db.Integer, primary_key=True)  # Identificador único de cada producto (clave primaria)
    name = db.Column(db.String(80), nullable=False)  # Nombre del producto, obligatorio
    category = db.Column(db.String(80), nullable=False)  # Categoría del producto, obligatoria
    price = db.Column(db.Float, nullable=False)  # Precio del producto, obligatorio
    description = db.Column(db.String(200), nullable=False)  # Descripción del producto, obligatoria
    status = db.Column(db.String(20), nullable=False, default='en venta')  # Estado del producto ('en venta', 'vendido', etc.), obligatorio
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ID del vendedor (clave foránea)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # ID del comprador (clave foránea, opcional)
    message = db.Column(db.String(200), nullable=True)  # Mensaje cifrado relacionado con el producto (opcional)
    created_at = db.Column(db.String(120), nullable=False)  # Fecha de creación del producto, obligatoria
    signature = db.Column(db.String(512), nullable=True)  # Firma digital del producto (opcional)
    buyer_certificate = db.Column(db.Text, nullable=True)  # Certificado del comprador, opcional

# Tabla de amigos (relaciones entre usuarios)
class Friend(db.Model):
    __tablename__ = 'friends'  # Nombre de la tabla en la base de datos
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)  # ID del usuario (clave primaria)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)  # ID del amigo (clave primaria)
    befriended_at = db.Column(db.String(120), nullable=False)  # Fecha en que se hizo la amistad, obligatoria
    user = db.relationship('User', foreign_keys=[user_id])  # Relación con el usuario
    friend = db.relationship('User', foreign_keys=[friend_id])  # Relación con el amigo


# Crear las tablas en la base de datos
with app.app_context():
    db.create_all()

# Generar el Certificado de la AC (CA)
CA_PRIVATE_KEY_PATH = os.path.join(basedir, 'ca_private_key.pem')
CA_CERTIFICATE_PATH = os.path.join(basedir, 'ca_certificate.pem')

def create_ca_certificate():
    # Comprobar si ya existe un certificado de CA
    if os.path.exists(CA_PRIVATE_KEY_PATH) and os.path.exists(CA_CERTIFICATE_PATH):
        print("Certificado CA ya existe.")
        return

    # Generar clave privada para la AC
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Guardar clave privada en archivo
    with open(CA_PRIVATE_KEY_PATH, 'wb') as f:
        f.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Crear datos del certificado de la AC
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CryptoWallapop CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CryptoWallapop Root CA"),
    ])

    # Crear certificado autofirmado de la AC
    ca_certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)  # Válido por 10 años
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())

    # Guardar certificado de la CA
    with open(CA_CERTIFICATE_PATH, 'wb') as f:
        f.write(
            ca_certificate.public_bytes(serialization.Encoding.PEM)
        )


create_ca_certificate()  # Generar certificado de la CA

# Rutas de la aplicación
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        nombre = request.form['nombre']
        ciudad = request.form['ciudad']
        email = request.form['email']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "El nombre de usuario ya está registrado."

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return "El correo electrónico ya está en uso."

        # Validar la fortaleza de la contraseña
        is_valid, error_message = validar_fortaleza(password)
        if not is_valid:
            return error_message

        password = password.encode()
        salt = os.urandom(16)
        key = derive_key(password, salt)

        # Generar claves pública y privada del usuario
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Cifrar la clave privada
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_private_key = encryptor.update(private_pem) + encryptor.finalize()

        # Crear el usuario en la base de datos
        user = User(
            username=username, nombre=nombre, ciudad=ciudad, email=email,
            key=key.hex(), salt=salt.hex(), created_at=now, updated_at=now
        )
        db.session.add(user)
        db.session.commit()

        # Firmar el Certificado del Usuario usando la CA
        # Cargar la clave privada y el certificado de la CA
        with open(CA_PRIVATE_KEY_PATH, 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(CA_CERTIFICATE_PATH, 'rb') as f:
            ca_certificate = x509.load_pem_x509_certificate(f.read())

        # Crear el certificado del usuario firmado por la CA
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ciudad),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CryptoWallapop"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        user_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_certificate.subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)  # Válido por 1 año
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(ca_private_key, hashes.SHA256())

        certificate_pem = user_certificate.public_bytes(serialization.Encoding.PEM)

        # Guardar las claves del usuario y el certificado
        user_keys = UserKeys(
            user_id=user.id,
            public_key=public_pem.decode(),
            private_key=(iv + encrypted_private_key).hex(),
            certificate=certificate_pem.decode()
        )
        db.session.add(user_keys)
        db.session.commit()

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

    # Obtener el mensaje del formulario y cifrarlo (con la clave privada del comprador)
    message = request.form['message']
    secret_key = bytes.fromhex(buyer.key)  # Convertir clave de hexadecimal a bytes

    # Cifrar el mensaje
    encrypted_message = encrypt_data(message, secret_key)

    # Desencriptar la clave privada para firmar
    user_keys = UserKeys.query.filter_by(user_id=buyer_id).first()
    encrypted_private_key = bytes.fromhex(user_keys.private_key)
    iv = encrypted_private_key[:16]
    encrypted_key = encrypted_private_key[16:]
    cipher = Cipher(algorithms.AES(secret_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    private_pem = decryptor.update(encrypted_key) + decryptor.finalize()
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    # Crear la firma digital del mensaje cifrado
    signature = private_key.sign(
        encrypted_message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Guardar el mensaje cifrado, la firma y el certificado en la base de datos
    product.message = encrypted_message
    product.signature = signature.hex()
    product.buyer_certificate = user_keys.certificate
    product.status = 'pendiente de confirmación'
    product.buyer_id = buyer_id
    db.session.commit()

    # Redirigir al flujo de compra
    return redirect(url_for('comprar', product=product, original_message=message, buyer=buyer))


@app.route('/validar_compra', methods=['POST'])
def validar_compra():
    try:
        product_id = request.form['product_id']
        buyer_id = request.form['buyer_id']

        product = Product.query.get(product_id)
        if not product:
            return "Error: Producto no encontrado.", 404

        buyer = User.query.get(product.buyer_id)
        if not buyer:
            return "Error: Comprador no encontrado.", 404

        secret_key = bytes.fromhex(buyer.key)

        encrypted_message = bytes.fromhex(product.message)
        signature = bytes.fromhex(product.signature)
        buyer_certificate_pem = product.buyer_certificate.encode()
        buyer_certificate = x509.load_pem_x509_certificate(buyer_certificate_pem)

        # Verificar que el certificado del comprador es válido
        if buyer_certificate.not_valid_before > datetime.now(timezone.utc) or buyer_certificate.not_valid_after < datetime.now(timezone.utc):
            return "El certificado del comprador no es válido.", 403

        # Verificar la firma usando la clave pública del certificado del comprador
        buyer_public_key = buyer_certificate.public_key()
        try:
            buyer_public_key.verify(
                signature,
                encrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return "La verificación de la firma ha fallado. Compra no autenticada.", 403

        # Si la verificación es correcta, descifrar el mensaje original
        original_message = decrypt_data(product.message, secret_key)

        product.status = 'vendido'
        product.buyer_id = buyer_id
        db.session.commit()

        buyer.objetos_comprados += f"{product.id},"
        db.session.commit()

        return redirect(url_for('productos'))

    except Exception as e:
        print(f"Error durante la validación de la compra: {e}")
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

        # Recuperar la clave privada del usuario
        user_keys = UserKeys.query.filter_by(user_id=seller_id).first()
        if not user_keys:
            return "Error: No se encontraron claves asociadas al usuario.", 400

        # Desencriptar la clave privada
        user = User.query.get(seller_id)
        key = bytes.fromhex(user.key)
        encrypted_private_key = bytes.fromhex(user_keys.private_key)
        iv = encrypted_private_key[:16]
        encrypted_key = encrypted_private_key[16:]
        # Descifrar clave privada
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        private_pem = decryptor.update(encrypted_key) + decryptor.finalize()
        # Cargar la clave privada
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
        )
        # Crear una firma digital de los datos relevantes del producto
        product_data = f"{name}|{category}|{price}|{description}".encode()
        signature = private_key.sign(
            product_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Crear un nuevo producto y guardarlo en la base de datos
        product = Product(name=name, category=category, price=price, description=description, created_at=now, seller_id=seller_id, signature=signature.hex())

        db.session.add(product)
        db.session.commit()

        # Actualizar el historial de productos vendidos del vendedor
        user = User.query.get(seller_id)
        user.objetos_vendidos += f"{product.id},"
        db.session.commit()

        print("Producto publicado exitosamente con firma digital.")
        return redirect(url_for('app_route'))
    return render_template('vender.html')


@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    product_id = request.form['product_id']
    product = Product.query.get(product_id)
    seller = User.query.get(product.seller_id)
    buyer = User.query.get(product.buyer_id)
    user_keys = UserKeys.query.filter_by(user_id=buyer.id).first()

    if not user_keys:
        return jsonify({"status": "error", "message": "User keys not found."})

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