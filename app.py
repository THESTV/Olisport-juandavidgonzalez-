from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Whitelist
from datetime import datetime
import os

app = Flask(__name__)

# ================================
# CONFIGURACIÓN
# ================================
app.config['SECRET_KEY'] = "clave_secreta_olisport"
db_path = os.path.join(os.path.dirname(__file__), "database", "olisport.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# ================================
# FLASK-LOGIN
# ================================
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================================
# HOME
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

# ================================
# REGISTRO
# ================================
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
            password_hash=generate_password_hash(password),
            rol="usuario"
        )
        db.session.add(nuevo)
        db.session.commit()

        flash("Cuenta creada correctamente. Ahora inicia sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ================================
# LOGIN
# ================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")

        usuario = User.query.filter_by(correo=correo).first()

        if not usuario:
            flash("El correo no está registrado.", "error")
            return render_template("login.html", correo=correo)

        if not check_password_hash(usuario.password_hash, password):
            flash("Contraseña incorrecta.", "error")
            return render_template("login.html", correo=correo)

        login_user(usuario)

        if usuario.rol == "admin":
            return redirect(url_for("panel_admin"))
        elif usuario.rol == "trabajador":
            if usuario.whitelist:
                return redirect(url_for("panel_trabajador"))
            else:
                flash("No estás autorizado para ingresar como trabajador.", "error")
                return redirect(url_for("market"))

        return redirect(url_for("market"))

    return render_template("login.html")

# ================================
# PERFIL
# ================================
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

# ================================
# MARKET
# ================================
@app.route("/market")
def market():
    return render_template("market.html")

# ================================
# PANEL ADMIN
# ================================
@app.route("/admin")
@login_required
def panel_admin():
    if current_user.rol != "admin":
        flash("Acceso denegado.", "error")
        return redirect(url_for("market"))

    usuarios = User.query.all()
    return render_template("panel_admin.html", usuario=current_user, usuarios=usuarios)

# ================================
# WHITELIST - AUTORIZAR
# ================================
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

    nueva_aut = Whitelist(
        id_usuario=id_usuario,
        fecha_autorizacion=datetime.utcnow()
    )
    db.session.add(nueva_aut)
    db.session.commit()

    flash("Usuario autorizado correctamente.", "success")
    return redirect(url_for("panel_admin"))

# ================================
# WHITELIST - DESAUTORIZAR
# ================================
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

    db.session.delete(usuario.whitelist)
    db.session.commit()

    flash("Autorización eliminada correctamente.", "success")
    return redirect(url_for("panel_admin"))

# ================================
# CAMBIO DE ROL
# ================================
@app.route("/cambiar_rol/<int:id_usuario>", methods=["POST"])
@login_required
def cambiar_rol(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("panel_admin"))

    usuario = User.query.get_or_404(id_usuario)
    if usuario.correo == "admin@olisport.com":
        flash("⚠ No puedes cambiar el rol del administrador principal.", "error")
        return redirect(url_for("panel_admin"))

    nuevo_rol = request.form.get("rol")
    if nuevo_rol not in ["admin", "trabajador", "usuario", "cliente"]:
        flash("Rol inválido", "error")
        return redirect(url_for("panel_admin"))

    usuario.rol = nuevo_rol
    db.session.commit()
    flash("Rol actualizado correctamente.", "success")
    return redirect(url_for("panel_admin"))

# ================================
# HACER CLIENTE
# ================================
@app.route("/hacer_usuario/<int:id_usuario>")
@login_required
def hacer_usuario(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("panel_admin"))

    usuario = User.query.get_or_404(id_usuario)
    if usuario.correo == "admin@olisport.com":
        flash("⚠ No puedes cambiar el rol del administrador principal.", "error")
        return redirect(url_for("panel_admin"))

    usuario.rol = "cliente"
    db.session.commit()
    flash("Rol cambiado a CLIENTE correctamente.", "success")
    return redirect(url_for("panel_admin"))

# ================================
# ELIMINAR USUARIO
# ================================
@app.route("/eliminar_usuario/<int:id_usuario>", methods=["POST"])
@login_required
def eliminar_usuario(id_usuario):
    if current_user.rol != "admin":
        flash("No autorizado", "error")
        return redirect(url_for("market"))

    usuario = User.query.get_or_404(id_usuario)

    if usuario.correo == "admin@olisport.com":
        flash("⚠ No puedes eliminar al administrador principal.", "error")
        return redirect(url_for("panel_admin"))

    if usuario.whitelist:
        db.session.delete(usuario.whitelist)

    db.session.delete(usuario)
    db.session.commit()

    flash("Usuario eliminado exitosamente.", "success")
    return redirect(url_for("panel_admin"))

# ================================
# PANEL TRABAJADOR
# ================================
@app.route("/trabajador")
@login_required
def panel_trabajador():
    if current_user.rol not in ["trabajador", "admin"]:
        flash("No autorizado.", "error")
        return redirect(url_for("market"))

    if current_user.rol == "trabajador" and not current_user.whitelist:
        flash("No estás en la whitelist.", "error")
        return redirect(url_for("market"))

    return render_template("trabajador.html", usuario=current_user)

# ================================
# LOGOUT
# ================================
@app.route("/logout")
def logout():
    logout_user()
    flash("Sesión cerrada correctamente", "success")
    return redirect(url_for("index"))

# ================================
# API
# ================================
@app.route('/api/usuarios', methods=['GET'])
def api_usuarios():
    usuarios = User.query.all()
    return jsonify([{"id": u.id, "nombre": u.nombre, "correo": u.correo} for u in usuarios])

@app.route('/api/whitelist', methods=['GET'])
def api_whitelist():
    items = Whitelist.query.all()
    return jsonify([{
        "id": w.id,
        "id_usuario": w.id_usuario,
        "fecha_autorizacion": w.fecha_autorizacion
    } for w in items])

# ================================
# CREAR ADMIN
# ================================
with app.app_context():
    os.makedirs("database", exist_ok=True)
    db.create_all()

    if not User.query.filter_by(correo="admin@olisport.com").first():
        admin = User(
            nombre="Administrador",
            correo="admin@olisport.com",
            password_hash=generate_password_hash("admin"),
            rol="admin"
        )
        db.session.add(admin)
        db.session.commit()

# ================================
# RUN
# ================================
if __name__ == '__main__':
    app.run(debug=True)
