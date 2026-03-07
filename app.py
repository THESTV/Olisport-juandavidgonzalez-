from flask import Flask, request, jsonify
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from models import db, User, Whitelist, Rol, UsuarioRol
from config import Config
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

CORS(app, origins=["http://localhost:3000"], supports_credentials=True)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ======================================================
# AUTH — LOGIN
# ======================================================
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    correo = data.get("correo", "").strip().lower()
    password = data.get("password", "")

    usuario = User.query.filter_by(correo=correo).first()
    if not usuario:
        return jsonify({"success": False, "error": "El correo no está registrado"}), 401
    if not usuario.check_password(password):
        return jsonify({"success": False, "error": "Contraseña incorrecta"}), 401

    return jsonify({
        "success": True,
        "user": {
            "id": usuario.id,
            "nombre": usuario.nombre,
            "correo": usuario.correo,
            "rol": usuario.rol,
            "whitelist": usuario.whitelist,
            "direccion": usuario.direccion or "",
        }
    })


# ======================================================
# AUTH — LOGIN CON GOOGLE
# ======================================================
@app.route("/api/google-login", methods=["POST"])
def api_google_login():
    data = request.get_json()
    correo = data.get("correo", "").strip().lower()
    nombre = data.get("nombre", "").strip()
    provider_id = data.get("provider_id")

    if not correo:
        return jsonify({"success": False, "error": "Correo requerido"}), 400

    usuario = User.query.filter_by(correo=correo).first()

    if not usuario:
        usuario = User(
            nombre=nombre,
            correo=correo,
            contrasena_hash=generate_password_hash(provider_id or "google_user"),
            rol="usuario",
            whitelist=False,
        )
        db.session.add(usuario)
        db.session.commit()

        # Asignar rol RBAC por defecto
        rol = Rol.query.filter_by(nombre="usuario").first()
        if rol:
            asignacion = UsuarioRol(usuario_id=usuario.id, rol_id=rol.id)
            db.session.add(asignacion)
            db.session.commit()

    return jsonify({
        "success": True,
        "user": {
            "id": usuario.id,
            "nombre": usuario.nombre,
            "correo": usuario.correo,
            "rol": usuario.rol,
            "whitelist": usuario.whitelist,
            "direccion": usuario.direccion or "",
        }
    })


# ======================================================
# AUTH — REGISTRO
# ======================================================
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    nombre = data.get("nombre", "").strip()
    correo = data.get("correo", "").strip().lower()
    password = data.get("password", "")

    if User.query.filter_by(correo=correo).first():
        return jsonify({"success": False, "error": "El correo ya está registrado"}), 400

    nuevo = User(
        nombre=nombre,
        correo=correo,
        contrasena_hash=generate_password_hash(password),
        rol="usuario"
    )
    db.session.add(nuevo)
    db.session.commit()

    # Asignar rol RBAC por defecto
    rol = Rol.query.filter_by(nombre="usuario").first()
    if rol:
        asignacion = UsuarioRol(usuario_id=nuevo.id, rol_id=rol.id)
        db.session.add(asignacion)
        db.session.commit()

    return jsonify({"success": True, "message": "Cuenta creada correctamente"})


# ======================================================
# PERFIL
# ======================================================
@app.route("/api/perfil", methods=["PUT"])
def api_perfil():
    data = request.get_json()
    user_id = data.get("id")

    usuario = User.query.get(user_id)
    if not usuario:
        return jsonify({"success": False, "error": "Usuario no encontrado"}), 404

    usuario.nombre = data.get("nombre", usuario.nombre)
    usuario.correo = data.get("correo", usuario.correo)
    usuario.direccion = data.get("direccion", usuario.direccion)

    nueva_pass = data.get("password")
    if nueva_pass:
        usuario.contrasena_hash = generate_password_hash(nueva_pass)

    db.session.commit()
    return jsonify({"success": True, "message": "Perfil actualizado correctamente"})


# ======================================================
# USUARIOS — Listar (Admin)
# ======================================================
@app.route("/api/usuarios", methods=["GET"])
def api_usuarios():
    usuarios = User.query.all()
    return jsonify({
        "usuarios": [
            {
                "id": u.id,
                "nombre": u.nombre,
                "correo": u.correo,
                "direccion": u.direccion or "",
                "rol": u.rol,
                "whitelist": u.whitelist,
                "roles_rbac": [ur.rol.to_dict() for ur in u.usuario_roles],
            }
            for u in usuarios
        ]
    })


# ======================================================
# USUARIOS — Crear (Admin)
# ======================================================
@app.route("/api/usuarios", methods=["POST"])
def api_crear_usuario():
    data = request.get_json()
    nombre = data.get("nombre")
    correo = data.get("correo")
    direccion = data.get("direccion", "")
    password = data.get("password") or "12345"
    rol_nombre = data.get("rol", "usuario")

    if User.query.filter_by(correo=correo).first():
        return jsonify({"success": False, "error": "El correo ya está registrado"}), 400

    nuevo = User(nombre=nombre, correo=correo, direccion=direccion, rol=rol_nombre)
    nuevo.set_password(password)
    db.session.add(nuevo)
    db.session.commit()

    # Asignar rol RBAC
    rol = Rol.query.filter_by(nombre=rol_nombre).first()
    if rol:
        asignacion = UsuarioRol(usuario_id=nuevo.id, rol_id=rol.id)
        db.session.add(asignacion)
        db.session.commit()

    return jsonify({"success": True, "message": "Usuario creado correctamente"})


# ======================================================
# USUARIOS — Editar (Admin)
# ======================================================
@app.route("/api/usuarios/<int:id_usuario>", methods=["PUT"])
def api_editar_usuario(id_usuario):
    usuario = User.query.get_or_404(id_usuario)

    if usuario.correo == "admin@olisport.com":
        return jsonify({"success": False, "error": "No puedes editar al admin principal"}), 403

    data = request.get_json()
    usuario.nombre = data.get("nombre", usuario.nombre)
    usuario.correo = data.get("correo", usuario.correo)
    usuario.direccion = data.get("direccion", usuario.direccion)

    nuevo_rol = data.get("rol")
    if nuevo_rol in ["usuario", "trabajador", "admin"]:
        usuario.rol = nuevo_rol
        # Sincronizar RBAC
        UsuarioRol.query.filter_by(usuario_id=id_usuario).delete()
        rol = Rol.query.filter_by(nombre=nuevo_rol).first()
        if rol:
            db.session.add(UsuarioRol(usuario_id=id_usuario, rol_id=rol.id))

    nueva_pass = data.get("password")
    if nueva_pass:
        usuario.contrasena_hash = generate_password_hash(nueva_pass)

    db.session.commit()
    return jsonify({"success": True, "message": "Usuario actualizado correctamente"})


# ======================================================
# USUARIOS — Eliminar (Admin)
# ======================================================
@app.route("/api/usuarios/<int:id_usuario>", methods=["DELETE"])
def api_eliminar_usuario(id_usuario):
    usuario = User.query.get_or_404(id_usuario)

    if usuario.correo == "admin@olisport.com":
        return jsonify({"success": False, "error": "No puedes eliminar al admin principal"}), 403

    if usuario.whitelist:
        w = Whitelist.query.filter_by(id_usuario=id_usuario).first()
        if w:
            db.session.delete(w)

    UsuarioRol.query.filter_by(usuario_id=id_usuario).delete()
    db.session.delete(usuario)
    db.session.commit()
    return jsonify({"success": True, "message": "Usuario eliminado correctamente"})


# ======================================================
# WHITELIST — Autorizar
# ======================================================
@app.route("/api/autorizar/<int:id_usuario>", methods=["POST"])
def api_autorizar(id_usuario):
    usuario = User.query.get_or_404(id_usuario)
    if usuario.whitelist:
        return jsonify({"success": False, "error": "Ya está autorizado"}), 400

    nueva_aut = Whitelist(id_usuario=id_usuario)
    usuario.whitelist = True
    db.session.add(nueva_aut)
    db.session.commit()
    return jsonify({"success": True, "message": "Usuario autorizado correctamente"})


# ======================================================
# WHITELIST — Desautorizar
# ======================================================
@app.route("/api/desautorizar/<int:id_usuario>", methods=["POST"])
def api_desautorizar(id_usuario):
    usuario = User.query.get_or_404(id_usuario)
    if not usuario.whitelist:
        return jsonify({"success": False, "error": "No estaba autorizado"}), 400

    w = Whitelist.query.filter_by(id_usuario=id_usuario).first()
    if w:
        db.session.delete(w)
    usuario.whitelist = False
    db.session.commit()
    return jsonify({"success": True, "message": "Autorización eliminada"})


# ======================================================
# ROLES — Listar
# ======================================================
@app.route("/api/roles", methods=["GET"])
def api_roles():
    roles = Rol.query.all()
    return jsonify({"roles": [r.to_dict() for r in roles]})


# ======================================================
# ROLES — Crear
# ======================================================
@app.route("/api/roles", methods=["POST"])
def api_crear_rol():
    data = request.get_json()
    nombre = data.get("nombre", "").strip().lower()
    permisos = data.get("permisos", {})

    if not nombre:
        return jsonify({"success": False, "error": "Nombre requerido"}), 400
    if Rol.query.filter_by(nombre=nombre).first():
        return jsonify({"success": False, "error": "El rol ya existe"}), 400

    rol = Rol(nombre=nombre, permisos_json=permisos)
    db.session.add(rol)
    db.session.commit()
    return jsonify({"success": True, "rol": rol.to_dict()})


# ======================================================
# ROLES — Editar
# ======================================================
@app.route("/api/roles/<int:rol_id>", methods=["PUT"])
def api_editar_rol(rol_id):
    rol = Rol.query.get_or_404(rol_id)
    data = request.get_json()
    rol.nombre = data.get("nombre", rol.nombre)
    rol.permisos_json = data.get("permisos", rol.permisos_json)
    db.session.commit()
    return jsonify({"success": True, "rol": rol.to_dict()})


# ======================================================
# ROLES — Eliminar
# ======================================================
@app.route("/api/roles/<int:rol_id>", methods=["DELETE"])
def api_eliminar_rol(rol_id):
    rol = Rol.query.get_or_404(rol_id)
    if rol.nombre in ["admin", "trabajador", "usuario"]:
        return jsonify({"success": False, "error": "No puedes eliminar roles base"}), 403
    db.session.delete(rol)
    db.session.commit()
    return jsonify({"success": True})


# ======================================================
# USUARIO_ROLES — Asignar rol
# ======================================================
@app.route("/api/usuarios/<int:id_usuario>/roles", methods=["POST"])
def api_asignar_rol(id_usuario):
    usuario = User.query.get_or_404(id_usuario)
    data = request.get_json()
    rol_id = data.get("rol_id")

    rol = Rol.query.get_or_404(rol_id)
    existe = UsuarioRol.query.filter_by(usuario_id=id_usuario, rol_id=rol_id).first()
    if existe:
        return jsonify({"success": False, "error": "El usuario ya tiene ese rol"}), 400

    asignacion = UsuarioRol(usuario_id=id_usuario, rol_id=rol_id)
    usuario.rol = rol.nombre
    db.session.add(asignacion)
    db.session.commit()
    return jsonify({"success": True, "message": f"Rol '{rol.nombre}' asignado correctamente"})


# ======================================================
# USUARIO_ROLES — Quitar rol
# ======================================================
@app.route("/api/usuarios/<int:id_usuario>/roles/<int:rol_id>", methods=["DELETE"])
def api_quitar_rol(id_usuario, rol_id):
    asignacion = UsuarioRol.query.filter_by(usuario_id=id_usuario, rol_id=rol_id).first()
    if not asignacion:
        return jsonify({"success": False, "error": "El usuario no tiene ese rol"}), 404
    db.session.delete(asignacion)
    db.session.commit()
    return jsonify({"success": True, "message": "Rol quitado correctamente"})


# ======================================================
# USUARIO_ROLES — Ver roles de usuario
# ======================================================
@app.route("/api/usuarios/<int:id_usuario>/roles", methods=["GET"])
def api_roles_usuario(id_usuario):
    usuario = User.query.get_or_404(id_usuario)
    roles = [ur.rol.to_dict() for ur in usuario.usuario_roles]
    return jsonify({"roles": roles})


# ======================================================
# PRODUCTOS
# ======================================================
@app.route("/api/productos", methods=["GET"])
def api_productos():
    return jsonify({"productos": []})


# ======================================================
# INIT
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

        # Asignar rol RBAC al admin si no tiene
        rol_admin = Rol.query.filter_by(nombre="admin").first()
        if rol_admin and admin:
            existe = UsuarioRol.query.filter_by(usuario_id=admin.id, rol_id=rol_admin.id).first()
            if not existe:
                db.session.add(UsuarioRol(usuario_id=admin.id, rol_id=rol_admin.id))
                db.session.commit()
                print("✔ Rol RBAC admin asignado")

    app.run(debug=True, port=5000)
