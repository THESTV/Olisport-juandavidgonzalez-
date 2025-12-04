from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Whitelist
import os
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Clave secreta
app.config['SECRET_KEY'] = "clave_secreta_olisport"

# Ruta DB
db_path = os.path.join(os.path.dirname(__file__), "database", "olisport.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------------
#           HOME
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
#           REGISTRO
# -----------------------------
# -----------------------------
#           REGISTRO
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        correo = request.form["correo"].strip().lower()
        password = request.form["password"]
        confirm = request.form["password2"]

        # Validar correo repetido
        user = User.query.filter_by(correo=correo).first()
        if user:
            flash("El correo ya está registrado", "error")
            return render_template("register.html")

        # Validar confirmación
        if password != confirm:
            flash("Las contraseñas no coinciden", "error")
            return render_template("register.html")

        # Crear usuario
        hashed = generate_password_hash(password)
        nuevo = User(nombre=nombre, correo=correo, password_hash=hashed)
        db.session.add(nuevo)
        db.session.commit()

        flash("Cuenta creada correctamente. Ahora inicia sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# -----------------------------
#             LOGIN
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form["correo"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(correo=correo).first()

        if not user:
            flash("Correo no encontrado. Verifique nuevamente.", "error")
            # Mantener correo en el formulario
            return render_template("login.html", correo=correo)

        if not check_password_hash(user.password_hash, password):
            flash("Contraseña incorrecta. Digítela nuevamente.", "error")
            # Mantener correo en el formulario
            return render_template("login.html", correo=correo)

        # LOGIN CORRECTO
        login_user(user)

        token = jwt.encode(
            {
                "id": user.id,
                "exp": datetime.utcnow() + timedelta(hours=3)
            },
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )

        flash("Inicio de sesión exitoso", "success")

        acceso = Whitelist.query.filter_by(id_usuario=user.id).first()
        if acceso:
            return redirect(url_for("admin"))

        return redirect(url_for("perfil"))

    return render_template("login.html")

# -----------------------------
#        PERFIL CLIENTE
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
    autorizado = Whitelist.query.filter_by(id_usuario=current_user.id).first()

    if not autorizado:
        return "Acceso no autorizado", 403

    return render_template("admin.html", usuario=current_user)


# -----------------------------
#            LOGOUT
# -----------------------------
@app.route('/logout')
def logout():
    session.pop("token", None)
    logout_user()
    flash("Sesión cerrada correctamente", "success")
    return redirect(url_for('index'))


# -----------------------------
#        API PARA POSTMAN
# -----------------------------
@app.route('/api/usuarios', methods=['GET'])
def api_usuarios():
    usuarios = User.query.all()
    data = [{
        "id": u.id,
        "nombre": u.nombre,
        "correo": u.correo
    } for u in usuarios]

    return jsonify(data)


@app.route('/api/whitelist', methods=['GET'])
def api_whitelist():
    items = Whitelist.query.all()
    data = [{
        "id": w.id,
        "id_usuario": w.id_usuario,
        "fecha_autorizacion": w.fecha_autorizacion
    } for w in items]

    return jsonify(data)


# Crear base de datos
with app.app_context():
    os.makedirs("database", exist_ok=True)
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
