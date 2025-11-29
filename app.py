from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Whitelist
import os

app = Flask(__name__)

# Clave para sesiones
app.config['SECRET_KEY'] = "clave_secreta_olisport"

# Ruta DB dentro de /database
db_path = os.path.join(os.path.dirname(__file__), "database", "olisport.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Config flask-login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------------
#         RUTAS PÚBLICAS
# -----------------------------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route('/servicio')
def servicio():
    return render_template("servicio.html")


# -----------------------------
#         REGISTRO
# -----------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        password = request.form['password']

        # Verificar si el correo existe
        usuario = User.query.filter_by(correo=correo).first()
        if usuario:
            flash("El correo ya está registrado", "error")
            return redirect(url_for('register'))

        nuevo_usuario = User(
            nombre=nombre,
            correo=correo,
            password_hash=generate_password_hash(password),
            rol="cliente"
        )

        db.session.add(nuevo_usuario)
        db.session.commit()

        flash("Usuario registrado correctamente. Ahora puedes iniciar sesión.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")


# -----------------------------
#         LOGIN
# -----------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        correo = request.form["correo"]
        password = request.form["password"]

        usuario = User.query.filter_by(correo=correo).first()

        if not usuario or not check_password_hash(usuario.password_hash, password):
            flash("Correo o contraseña incorrectos", "error")
            return redirect(url_for("login"))

        login_user(usuario)

        # 🔥 REDIRECCIÓN SEGÚN ROL 🔥
        if usuario.rol == "admin":
            return redirect(url_for("admin"))

        # Cliente → Perfil
        return redirect(url_for("perfil"))

    return render_template("login.html")


# -----------------------------
#      PERFIL CLIENTE
# -----------------------------
@app.route("/perfil")
@login_required
def perfil():
    return render_template("perfil.html", usuario=current_user)


# -----------------------------
#         ADMIN PANEL
# -----------------------------
@app.route('/admin')
@login_required
def admin():

    # Validar si está en whitelist
    acceso = Whitelist.query.filter_by(id_usuario=current_user.id).first()

    if not acceso:
        return "Acceso no autorizado"

    return render_template("admin.html", usuario=current_user)


# -----------------------------
#         PERFIL DEL USUARIO
# -----------------------------
@app.route('/perfil')
@login_required
def perfil():
    return render_template("perfil.html", usuario=current_user)


# -----------------------------
#         LOGOUT
# -----------------------------
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# Crear BD si no existe
with app.app_context():
    os.makedirs("database", exist_ok=True)
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
