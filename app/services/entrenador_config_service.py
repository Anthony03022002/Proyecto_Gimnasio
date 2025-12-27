# app/services/servicio_configuracion_entrenador.py
from bson import ObjectId
from datetime import datetime
import app.extensions as extensions
from app.extensions import bcrypt


def get_users_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["users"]


def obtener_entrenador_por_username(username: str):
    users = get_users_collection()
    return users.find_one({"username": username, "role": "entrenador"})


def actualizar_perfil_entrenador(entrenador_id: str, username=None, nombre=None, email=None, telefono=None):
    users = get_users_collection()
    _id = ObjectId(str(entrenador_id))

    ent = users.find_one({"_id": _id, "role": "entrenador"})
    if not ent:
        raise ValueError("Entrenador no encontrado.")

    # username único si cambia
    if username and username != ent.get("username"):
        if users.find_one({"username": username, "_id": {"$ne": _id}}):
            raise ValueError("Ese username ya está en uso.")

    update = {"updated_at": datetime.utcnow()}
    if username is not None and username.strip() != "":
        update["username"] = username.strip()

    if nombre is not None:
        update["nombre"] = (nombre or "").strip() or None
    if email is not None:
        update["email"] = (email or "").strip() or None
    if telefono is not None:
        update["telefono"] = (telefono or "").strip() or None

    users.update_one({"_id": _id}, {"$set": update})
    return users.find_one({"_id": _id})


def cambiar_password_entrenador(entrenador_id: str, password_actual: str, password_nuevo: str):
    users = get_users_collection()
    _id = ObjectId(str(entrenador_id))

    ent = users.find_one({"_id": _id, "role": "entrenador"})
    if not ent:
        raise ValueError("Entrenador no encontrado.")

    if not bcrypt.check_password_hash(ent["password"], password_actual):
        raise ValueError("La contraseña actual no es correcta.")

    password_nuevo = (password_nuevo or "").strip()
    if len(password_nuevo) < 6:
        raise ValueError("La nueva contraseña debe tener al menos 6 caracteres.")

    nuevo_hash = bcrypt.generate_password_hash(password_nuevo).decode("utf-8")
    users.update_one(
        {"_id": _id},
        {"$set": {"password": nuevo_hash, "updated_at": datetime.utcnow()}}
    )
