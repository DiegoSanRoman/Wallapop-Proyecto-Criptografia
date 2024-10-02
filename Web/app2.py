from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

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
        nombre = request.form['nombre']
        ciudad = request.form['ciudad']
        email = request.form['email']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user = User(username=username, nombre=nombre, ciudad=ciudad, email=email, created_at=now, updated_at=now)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Asegúrate de que este nombre coincida con el atributo 'name' en tu formulario HTML
        user = User.query.filter_by(username=username).first()
        if user:
            # Aquí es donde verificarías la contraseña del usuario.
            # Como no veo que estés almacenando una contraseña en tu modelo de usuario,
            # no puedo proporcionar el código exacto para esto.
            # Pero aquí hay un ejemplo de cómo podrías hacerlo si estuvieras almacenando una contraseña hasheada:
            # if check_password_hash(user.password, password):
            #     return redirect(url_for('app_route'))
            # else:
            #     return "Contraseña incorrecta, por favor intenta de nuevo."
            return redirect(url_for('app_route'))
        else:
            return "Usuario no encontrado, por favor regístrate."
    return render_template('login.html')

@app.route('/app_route')
def app_route():
    return render_template('app.html')

if __name__ == '__main__':
    app.run(debug=True)