from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Whitelist
import os
from datetime import datetime

app = Flask(__name__)

# ================================
#         CONFIGURACIÓN
# ================================
app.config['SECRET_KEY'] = "clave_secreta_olisport"

db_path = os.path.join(os.path.dirname(__file__), "database", "olisport.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# ================================
#        FLASK-LOGIN
# ================================
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ================================
#              HOME
# ================================
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


# ==================================================
#                  REGISTRO
# ==================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        correo = request.form["correo"].strip().lower()
        password = request.form["password"]
        confirm = request.form["password2"]

        # Validar si ya existe
        user = User.query.filter_by(correo=correo).first()
        if user:
            flash("El correo ya está registrado", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Las contraseñas no coinciden", "error")
            return render_template("register.html")

        # Crear usuario
        hashed = generate_password_hash(password)

        nuevo = User(
            nombre=nombre,
            correo=correo,
            password_hash=hashed,
            rol="admin" if correo == "admin@olisport.com" else "usuario"
        )

        db.session.add(nuevo)
        db.session.commit()

        flash("Cuenta creada correctamente. Ahora inicia sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ==================================================
#                     LOGIN
# ==================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo").strip().lower()
        password = request.form.get("password")

        usuario = User.query.filter_by(correo=correo).first()

        if not usuario:
            flash("El correo no está registrado.", "error")
            return render_template("login.html", correo=correo)

        if not check_password_hash(usuario.password_hash, password):
            flash("Contraseña incorrecta.", "error")
            return render_template("login.html", correo=correo)

        login_user(usuario)

        # Redirección según rol
        if usuario.rol == "admin":
            return redirect(url_for("panel_admin"))

        elif usuario.rol == "trabajador":
            if usuario.whitelist:
                return redirect(url_for("panel_trabajador"))
            else:
                flash("No estás autorizado. Serás enviado a Market.", "error")
                return redirect(url_for("market"))

        else:
            return redirect(url_for("market"))

    return render_template("login.html")


# ==================================================
#                 PERFIL
# ==================================================
@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    if request.method == "POST":
        usuario = current_user
        usuario.nombre = request.form["nombre"]
        usuario.correo = request.form["correo"]

        nueva_pass = request.form.get("password")
        if nueva_pass:
            usuario.password_hash = generate_password_hash(nueva_pass)

        db.session.commit()

        flash("Actualización exitosa.", "success")

    return render_template("perfil.html", usuario=current_user)


# ==================================================
#                    MARKET
# ==================================================
@app.route("/market")
def market():
    return render_template("market.html")


# ==================================================
#               PANEL ADMINISTRADOR
# ==================================================
@app.route("/admin")
@login_required
def panel_admin():
    if current_user.rol != "admin":
        flash("Acceso denegado. Solo admin puede entrar aquí.", "error")
        return redirect(url_for("market"))

    usuarios = User.query.all()
    return render_template("panel_admin.html", usuario=current_user, usuarios=usuarios)


# ==================================================
#         WHITELIST: AUTORIZAR / DESAUTORIZAR
# ==================================================
@app.route("/autorizar/<int:user_id>")
@login_required
def autorizar_usuario(user_id):
    # Solo admin puede autorizar
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("market"))

    usuario = User.query.get_or_404(user_id)

    # Si ya está autorizado, no creamos doble whitelist
    if usuario.whitelist:
        flash("El usuario ya está autorizado.", "warning")
        return redirect(url_for("panel_admin"))

    # Crear autorización
    nueva_autorizacion = Whitelist(
        id_usuario=user_id,
        fecha_autorizacion="Autorizado"
    )

    db.session.add(nueva_autorizacion)
    db.session.commit()

    flash("Usuario autorizado correctamente.", "success")
    return redirect(url_for("panel_admin"))


@app.route("/desautorizar/<int:user_id>")
@login_required
def desautorizar_usuario(user_id):
    # Solo admin puede desautorizar
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("market"))

    usuario = User.query.get_or_404(user_id)

    if not usuario.whitelist:
        flash("El usuario no estaba autorizado.", "warning")
        return redirect(url_for("panel_admin"))

    # Eliminar whitelist del usuario
    db.session.delete(usuario.whitelist)
    db.session.commit()

    flash("Autorización eliminada correctamente.", "success")
    return redirect(url_for("panel_admin"))


# ==================================================
#                CAMBIO DE ROL
# ==================================================
@app.route("/cambiar_rol/<int:id_usuario>/<rol>")
@login_required
def cambiar_rol(id_usuario, rol):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("panel_admin"))

    if rol not in ["admin", "trabajador", "usuario"]:
        flash("Rol inválido", "error")
        return redirect(url_for("panel_admin"))

    usuario = User.query.get_or_404(id_usuario)
    usuario.rol = rol
    db.session.commit()

    flash("Rol actualizado correctamente", "success")
    return redirect(url_for("panel_admin"))


# ==================================================
#               PANEL TRABAJADOR
# ==================================================
@app.route("/trabajador")
@login_required
def panel_trabajador():

    if current_user.rol != "trabajador":
        flash("No estás autorizado. Serás enviado a Market.", "error")
        return redirect(url_for("market"))

    if not current_user.whitelist:
        flash("No estás en la whitelist. Serás enviado a Market.", "error")
        return redirect(url_for("market"))

    return render_template("trabajador.html", usuario=current_user)


# ==================================================
#                   LOGOUT
# ==================================================
@app.route("/logout")
def logout():
    logout_user()
    flash("Sesión cerrada correctamente", "success")
    return redirect(url_for("index"))


# ==================================================
#               API (Opcional)
# ==================================================
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


# ==================================================
#         CREAR DB AUTOMÁTICAMENTE
# ==================================================
with app.app_context():
    os.makedirs("database", exist_ok=True)
    db.create_all()


# ==================================================
#                 EJECUCIÓN
# ==================================================
if __name__ == '__main__':
    app.run(debug=True)
