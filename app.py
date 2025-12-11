from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash
from models import db, User, Whitelist
from datetime import datetime
from config import Config

app = Flask(__name__)

# CONFIGURACIÓN
app.config.from_object(Config)
db.init_app(app)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ======================================================
# RUTAS BÁSICAS
# ======================================================
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


# ======================================================
# REGISTRO
# ======================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        correo = request.form["correo"].strip().lower()
        password = request.form["password"]
        confirm = request.form["password2"]

        if User.query.filter_by(correo=correo).first():
            flash("El correo ya está registrado", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Las contraseñas no coinciden", "error")
            return render_template("register.html")

        nuevo = User(
            nombre=nombre,
            correo=correo,
            contrasena_hash=generate_password_hash(password),
            rol="usuario"
        )
        db.session.add(nuevo)
        db.session.commit()

        flash("Cuenta creada correctamente.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ======================================================
# LOGIN
# ======================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")

        usuario = User.query.filter_by(correo=correo).first()

        if not usuario:
            flash("El correo no está registrado.", "error")
            return render_template("login.html", correo=correo)

        if not usuario.check_password(password):
            flash("Contraseña incorrecta.", "error")
            return render_template("login.html", correo=correo)

        login_user(usuario)

        if usuario.rol == "admin":
            return redirect(url_for("panel_admin"))
        elif usuario.rol == "trabajador":
            if usuario.whitelist:
                return redirect(url_for("panel_trabajador"))
            else:
                flash("No estás autorizado.", "error")
                return redirect(url_for("market"))

        return redirect(url_for("market"))

    return render_template("login.html")


# ======================================================
# PERFIL
# ======================================================
@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    if request.method == "POST":
        usuario = current_user
        usuario.nombre = request.form["nombre"]
        usuario.correo = request.form["correo"]

        nueva_pass = request.form.get("password")
        if nueva_pass:
            usuario.contrasena_hash = generate_password_hash(nueva_pass)

        db.session.commit()
        flash("Actualización exitosa.", "success")

    return render_template("perfil.html", usuario=current_user)


# ======================================================
# MARKET
# ======================================================
@app.route("/market")
def market():
    return render_template("market.html")


# ======================================================
# PANEL ADMIN
# ======================================================
@app.route("/admin")
@login_required
def panel_admin():
    if current_user.rol != "admin":
        flash("Acceso denegado.", "error")
        return redirect(url_for("market"))

    usuarios = User.query.all()
    return render_template("panel_admin.html", usuario=current_user, usuarios=usuarios)


# ======================================================
# CREAR USUARIO (CORREGIDO)
# ======================================================
@app.route('/crear_usuario', methods=['POST'])
@login_required
def crear_usuario():
    nombre = request.form.get("nombre")
    correo = request.form.get("correo")
    direccion = request.form.get("direccion") or ""
    password = request.form.get("password")
    rol = request.form.get("rol")

    # Contraseña por defecto
    if not password or password.strip() == "":
        password = "12345"

    nuevo = User(
        nombre=nombre,
        correo=correo,
        direccion=direccion,
        rol=rol
    )

    nuevo.set_password(password)

    db.session.add(nuevo)
    db.session.commit()

    return redirect(url_for("panel_admin"))



# ======================================================
# EDITAR USUARIO (CORREGIDO)
# ======================================================
@app.route("/editar_usuario/<int:id_usuario>", methods=["POST"])
@login_required
def editar_usuario(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("panel_admin"))

    usuario = User.query.get_or_404(id_usuario)

    # Evitar editar al admin principal
    if usuario.correo == "admin@olisport.com":
        flash("No puedes editar al admin principal.", "error")
        return redirect(url_for("panel_admin"))

    usuario.nombre = request.form.get("nombre")
    usuario.correo = request.form.get("correo")
    usuario.direccion = request.form.get("direccion")

    # NUEVO → cambio de rol desde el modal
    nuevo_rol = request.form.get("rol")
    if nuevo_rol in ["usuario", "trabajador", "admin"]:
        usuario.rol = nuevo_rol

    # Cambio de contraseña
    nueva_pass = request.form.get("password")
    if nueva_pass:
        usuario.contrasena_hash = generate_password_hash(nueva_pass)

    db.session.commit()
    flash("Usuario actualizado correctamente.", "success")
    return redirect(url_for("panel_admin"))


# ======================================================
# WHITELIST
# ======================================================
@app.route("/autorizar/<int:id_usuario>")
@login_required
def autorizar_usuario(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("market"))

    usuario = User.query.get_or_404(id_usuario)

    if usuario.whitelist:
        flash("El usuario ya está autorizado.", "warning")
        return redirect(url_for("panel_admin"))

    nueva_aut = Whitelist(id_usuario=id_usuario)
    usuario.whitelist = True

    db.session.add(nueva_aut)
    db.session.commit()

    flash("Usuario autorizado.", "success")
    return redirect(url_for("panel_admin"))


@app.route("/desautorizar/<int:id_usuario>")
@login_required
def desautorizar_usuario(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("market"))

    usuario = User.query.get_or_404(id_usuario)

    if not usuario.whitelist:
        flash("El usuario no estaba autorizado.", "warning")
        return redirect(url_for("panel_admin"))

    w = Whitelist.query.filter_by(id_usuario=id_usuario).first()
    if w:
        db.session.delete(w)

    usuario.whitelist = False
    db.session.commit()

    flash("Autorización eliminada.", "success")
    return redirect(url_for("panel_admin"))


# ======================================================
# CAMBIO DE ROL
# ======================================================
@app.route("/cambiar_rol/<int:id_usuario>", methods=["POST"])
@login_required
def cambiar_rol(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("panel_admin"))

    usuario = User.query.get_or_404(id_usuario)

    if usuario.correo == "admin@olisport.com":
        flash("No puedes cambiar el rol del admin principal.", "error")
        return redirect(url_for("panel_admin"))

    nuevo_rol = request.form.get("rol")

    if nuevo_rol not in ["admin", "trabajador", "usuario"]:
        flash("Rol inválido", "error")
        return redirect(url_for("panel_admin"))

    usuario.rol = nuevo_rol
    db.session.commit()

    flash("Rol actualizado.", "success")
    return redirect(url_for("panel_admin"))


# ======================================================
# ELIMINAR USUARIO
# ======================================================
@app.route("/eliminar_usuario/<int:id_usuario>", methods=["POST"])
@login_required
def eliminar_usuario(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("panel_admin"))

    usuario = User.query.get_or_404(id_usuario)

    if usuario.correo == "admin@olisport.com":
        flash("No puedes eliminar al administrador principal.", "error")
        return redirect(url_for("panel_admin"))

    if usuario.whitelist:
        w = Whitelist.query.filter_by(id_usuario=id_usuario).first()
        if w:
            db.session.delete(w)

    db.session.delete(usuario)
    db.session.commit()

    flash("Usuario eliminado.", "success")
    return redirect(url_for("panel_admin"))


# ======================================================
# PANEL TRABAJADOR
# ======================================================
@app.route("/trabajador")
@login_required
def panel_trabajador():
    if current_user.rol not in ["trabajador", "admin"]:
        flash("No autorizado.", "error")
        return redirect(url_for("market"))

    if current_user.rol == "trabajador" and not current_user.whitelist:
        flash("No estás autorizado.", "error")
        return redirect(url_for("market"))

    return render_template("trabajador.html", usuario=current_user)


# ======================================================
# LOGOUT
# ======================================================
@app.route("/logout")
def logout():
    logout_user()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("index"))


# ======================================================
# RUN + CREAR ADMIN
# ======================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        admin = User.query.filter_by(correo="admin@olisport.com").first()
        if admin is None:
            admin = User(
                nombre="Admin",
                correo="admin@olisport.com",
                contrasena_hash=generate_password_hash("12345"),
                rol="admin",
                whitelist=True
            )
            db.session.add(admin)
            db.session.commit()
            print("✔ Admin creado correctamente")
        else:
            print("✔ Admin ya existe")

    app.run(debug=True)
