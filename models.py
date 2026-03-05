from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ============================================================
#  MODELO USER
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)

    nombre = db.Column(db.String(100), nullable=False)
    correo = db.Column(db.String(150), unique=True, nullable=False)

    # 🔐 Password (puede ser NULL si es login con Google)
    contrasena_hash = db.Column(db.String(255), nullable=True)

    direccion = db.Column(db.String(255))

    rol = db.Column(db.String(20), default="usuario")
    whitelist = db.Column(db.Boolean, default=False)

    # 🔵 OAuth
    provider = db.Column(db.String(50), nullable=True)
    provider_id = db.Column(db.String(255), nullable=True)

    # ============================================================
    # MANEJO DE CONTRASEÑA
    # ============================================================
    def set_password(self, password):
        self.contrasena_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.contrasena_hash:
            return False
        return check_password_hash(self.contrasena_hash, password)

    def get_id(self):
        return str(self.id)


# ============================================================
#  MODELO WHITELIST
# ============================================================
class Whitelist(db.Model):
    __tablename__ = "whitelist"

    id = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey("usuarios.id"))