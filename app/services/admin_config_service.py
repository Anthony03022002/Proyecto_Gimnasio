# app/services/servicio_configuracion_admin.py
from bson import ObjectId
from datetime import datetime, timezone

import app.extensions as extensions
from app.extensions import bcrypt


def _db():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db


def coleccion_usuarios():
    return _db()["users"]


def coleccion_configuracion():
    return _db()["settings"]


def obtener_admin_por_username(username: str):
    return coleccion_usuarios().find_one({"username": username, "role": "admin"})


def actualizar_perfil_admin(admin_id: str, username=None, nombre=None, email=None, telefono=None, activo=None):
    usuarios = coleccion_usuarios()
    _id = ObjectId(admin_id)

    admin = usuarios.find_one({"_id": _id, "role": "admin"})
    if not admin:
        raise ValueError("Administrador no encontrado.")

    if username and username != admin.get("username"):
        if usuarios.find_one({"username": username, "_id": {"$ne": _id}}):
            raise ValueError("Ese username ya está en uso.")

    cambios = {}  

    if username is not None and username.strip() != "":
        cambios["username"] = username.strip()
    if nombre is not None:
        cambios["nombre"] = nombre.strip()
    if email is not None:
        cambios["email"] = email.strip()
    if telefono is not None:
        cambios["telefono"] = telefono.strip()
    if activo is not None:
        cambios["activo"] = bool(activo)

    if cambios:
        usuarios.update_one({"_id": _id}, {"$set": cambios})

    return usuarios.find_one({"_id": _id})




def cambiar_password_admin(admin_id: str, password_actual: str, password_nuevo: str):
    usuarios = coleccion_usuarios()
    _id = ObjectId(admin_id)

    admin = usuarios.find_one({"_id": _id, "role": "admin"})
    if not admin:
        raise ValueError("Administrador no encontrado.")

    if not bcrypt.check_password_hash(admin["password"], password_actual):
        raise ValueError("La contraseña actual no es correcta.")

    if not password_nuevo or len(password_nuevo) < 6:
        raise ValueError("La nueva contraseña debe tener al menos 6 caracteres.")

    nuevo_hash = bcrypt.generate_password_hash(password_nuevo).decode("utf-8")
    usuarios.update_one(
        {"_id": _id},
        {"$set": {"password": nuevo_hash}}
    )


def obtener_configuracion_app():
    col = coleccion_configuracion()
    doc = col.find_one({"_id": "app"})
    if doc:
        return doc

    base = {
        "_id": "app",
        "gym_nombre": "Mi Gimnasio",
        "gym_direccion": "",
        "gym_telefono": "",
    }
    col.insert_one(base)
    return base


def actualizar_configuracion_app(gym_nombre=None, gym_direccion=None, gym_telefono=None):
    col = coleccion_configuracion()
    cambios = {"updated_at": datetime.now(timezone.utc)}

    if gym_nombre is not None:
        cambios["gym_nombre"] = gym_nombre.strip()
    if gym_direccion is not None:
        cambios["gym_direccion"] = gym_direccion.strip()
    if gym_telefono is not None:
        cambios["gym_telefono"] = gym_telefono.strip()

    col.update_one({"_id": "app"}, {"$set": cambios}, upsert=True)
    return col.find_one({"_id": "app"})
