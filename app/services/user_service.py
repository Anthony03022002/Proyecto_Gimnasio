from bson import ObjectId
from app.extensions import bcrypt
import app.extensions as extensions
from app.services.clientes import crear_o_actualizar_cliente
from app.services.contrasenas import generar_password


def get_users_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado. Asegúrate de llamar init_extensions(app) antes de usar la base de datos.")
    return db["users"]


def create_default_admin():
    users = get_users_collection()
    existing_admin = users.find_one({"role": "admin"})
    if existing_admin:
        return

    password_hash = bcrypt.generate_password_hash("admin123").decode("utf-8")

    users.insert_one({
        "username": "admin",
        "password": password_hash,
        "role": "admin"
    })

    print("✅ Usuario administrador creado por defecto: admin / admin123")



def create_cajero(username, password, nombre=None):
    users = get_users_collection()

    existing = users.find_one({"username": username})
    if existing:
        raise ValueError("Ya existe un usuario con ese username.")

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    doc = {
        "username": username,
        "password": password_hash,
        "role": "cajero",
        "nombre": nombre,
    }

    users.insert_one(doc)
    return doc

def update_cajero(cajero_id, username=None, nombre=None):
    users = get_users_collection()

    _id = ObjectId(cajero_id)
    cajero = users.find_one({"_id": _id, "role": "cajero"})
    if not cajero:
        raise ValueError("Cajero no encontrado.")

    # si cambia username, validar que no exista en otro
    if username and username != cajero.get("username"):
        if users.find_one({"username": username, "_id": {"$ne": _id}}):
            raise ValueError("Ese username ya está en uso.")

    update = {}
    if username is not None:
        update["username"] = username
    if nombre is not None:
        update["nombre"] = nombre

    if update:
        users.update_one({"_id": _id}, {"$set": update})

# 🔹 NUEVO: listar cajeros
def list_cajeros():
    users = get_users_collection()
    return list(users.find({"role": "cajero"}))


def reset_password_cajero(cajero_id, new_password):
    users = get_users_collection()
    _id = ObjectId(cajero_id)

    cajero = users.find_one({"_id": _id, "role": "cajero"})
    if not cajero:
        raise ValueError("Cajero no encontrado.")

    password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    users.update_one({"_id": _id}, {"$set": {"password": password_hash}})
    
def delete_cajero(cajero_id):
    users = get_users_collection()
    _id = ObjectId(cajero_id)

    cajero = users.find_one({"_id": _id, "role": "cajero"})
    if not cajero:
        raise ValueError("Cajero no encontrado.")

    users.delete_one({"_id": _id})


def find_or_create_cliente(identificacion, nombre, email=None, telefono=None):
    users = get_users_collection()

    cliente_info = {
        "identificacion": identificacion,
        "nombre": nombre,
        "email": email,
        "telefono": telefono,
    }

    user = users.find_one({"identificacion": identificacion})
    if user:
        if user.get("role") != "cliente":
            users.update_one({"_id": user["_id"]}, {"$set": {"role": "cliente"}})
            user["role"] = "cliente"

        # ✅ Guardar/actualizar en clientes con el mismo _id
        crear_o_actualizar_cliente(user["_id"], cliente_info)

        return user, None

    # crear nuevo user
    username = identificacion
    password_plain = generar_password(10)
    password_hash = bcrypt.generate_password_hash(password_plain).decode("utf-8")

    doc = {
        "username": username,
        "password": password_hash,
        "role": "cliente",
        "must_change_password": True,
        **cliente_info
    }

    result = users.insert_one(doc)
    doc["_id"] = result.inserted_id

    # ✅ Crear en clientes con _id = doc["_id"]
    crear_o_actualizar_cliente(doc["_id"], cliente_info)

    return doc, password_plain


