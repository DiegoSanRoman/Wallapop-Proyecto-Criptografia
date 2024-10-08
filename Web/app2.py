from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'basededatos/basededatos.db')
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
                return redirect(url_for('app_route'))
            else:
                return "Contraseña incorrecta, por favor intenta de nuevo."
        else:
            return "Usuario no encontrado, por favor regístrate."
    return render_template('login.html')

@app.route('/app_route')
def app_route():
    return render_template('app.html')

@app.route('/comprar')
def comprar():
    return render_template('comprar.html')

@app.route('/vender')
def vender():
    return render_template('vender.html')


if __name__ == '__main__':
    app.run(debug=True)