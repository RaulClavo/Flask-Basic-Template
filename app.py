import sqlite3

from flask import Flask, redirect, url_for, session, render_template, request, flash, abort, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Configuración de Flask
app = Flask(__name__)
app.secret_key = '123'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Lista de correos de administradores
ADMIN_EMAILS = ['admin@gmail.com']

# Base de datos
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Crear tabla de usuarios si no existe
    c.execute('''CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT, role TEXT, name TEXT)''')
    conn.commit()
    conn.close()

# Modelo de Usuario
class User(UserMixin):
    def __init__(self, email, role, name):
        self.id = email
        self.role = role
        self.name = name

# Cargar usuario
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT email, role, name FROM users WHERE email = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

# Ruta para iniciar sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT password, role, name FROM users WHERE email = ?', (email,))
        user_data = c.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data[0], password):
            user = User(email, user_data[1], user_data[2])
            login_user(user)
            return redirect(url_for('admin')) if user.role == 'admin' else redirect(url_for('index'))
        else:
            flash('Correo o contraseña incorrectos.')

    return render_template('login.html')

# Ruta para registrarse
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if 'register' in request.form:

            email = request.form['email']
            password = request.form['password']
            name = request.form['name']
            role = 'admin' if email in ADMIN_EMAILS else 'usuario'

            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            if c.fetchone():
                flash('El correo ya está registrado.')
            else:
                hashed_password = generate_password_hash(password)
                c.execute('INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)',
                          (email, hashed_password, role, name))
                conn.commit()
                flash('Registro exitoso. Puedes iniciar sesión ahora.')
            conn.close()

            return redirect(url_for('index'))
    return render_template('register.html')

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Ruta de administrador (solo accesible para admin)
@app.route('/admin')
@login_required
def admin():
    if current_user.id not in ADMIN_EMAILS:
        return "Acceso denegado", 403

    # Renderizar la plantilla admin.html y pasar la lista de locales
    return render_template('admin.html', user=current_user)

# Ruta principal (pantalla de inicio)
@app.route('/')
def index():
    # Inicializar variables de usuario
    role = None

    # Si el usuario está autenticado, obtener sus locales
    if current_user.is_authenticated:
        role = current_user.role
        user_email = current_user.id  # El correo del usuario autenticado

    # Pasar la lista de todos los locales y los locales del usuario a la plantilla
    return render_template('index.html', user=current_user)

init_db()
app.run(host='0.0.0.0')

