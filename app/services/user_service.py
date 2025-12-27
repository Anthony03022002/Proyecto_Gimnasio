from bson import ObjectId
from app.extensions import bcrypt
import app.extensions as extensions
from app.services.clientes import crear_o_actualizar_cliente, get_clientes_collection
from app.services.contrasenas import generar_password
from datetime import datetime



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
    clientes_col = get_clientes_collection()

    identificacion = (identificacion or "").strip()
    nombre = (nombre or "").strip()
    email = (email or "").strip() if email else None
    telefono = (telefono or "").strip() if telefono else None

    if not identificacion:
        raise ValueError("identificacion es obligatoria")
    if not nombre:
        raise ValueError("nombre es obligatorio")

    cliente_info = {
        "identificacion": identificacion,
        "nombre": nombre,
        "email": email,
        "telefono": telefono,
        "updated_at": datetime.utcnow(),
    }

    cliente_existente = clientes_col.find_one({"identificacion": identificacion}, {"_id": 1})

    if cliente_existente:
        user_id = cliente_existente["_id"]

        user = users.find_one({"_id": user_id})
        if not user:
            raise RuntimeError("Cliente existe pero no existe usuario asociado.")

        if user.get("role") != "cliente":
            users.update_one({"_id": user_id}, {"$set": {"role": "cliente"}})
            user["role"] = "cliente"

        if user.get("cliente_id") != user_id:
            users.update_one({"_id": user_id}, {"$set": {"cliente_id": user_id}})
            user["cliente_id"] = user_id

        crear_o_actualizar_cliente(user_id, cliente_info)

        return user, None

    user_id = ObjectId()  
    username = identificacion
    password_plain = generar_password(10)
    password_hash = bcrypt.generate_password_hash(password_plain).decode("utf-8")

    user_doc = {
        "_id": user_id,
        "cliente_id": user_id,          
        "username": username,
        "password": password_hash,
        "role": "cliente",
        "must_change_password": True,
        "created_at": datetime.utcnow(),
    }

    users.insert_one(user_doc)

    crear_o_actualizar_cliente(user_id, cliente_info)

    return user_doc, password_plain


def listar_usuarios(filtro=None):
    users = get_users_collection()
    q = filtro or {}
    return list(users.find(q).sort("username", 1))

def obtener_usuario_por_id(user_id):
    users = get_users_collection()
    try:
        oid = ObjectId(str(user_id))
    except Exception:
        return None
    return users.find_one({"_id": oid})


    
def actualizar_usuario_completo(user_id, data):

    users = get_users_collection()

    try:
        oid = ObjectId(str(user_id))
    except Exception:
        raise ValueError("ID inválido")

    user = users.find_one({"_id": oid})
    if not user:
        raise ValueError("Usuario no encontrado")

    update = {}

    username = (data.get("username") or "").strip()
    if not username:
        raise ValueError("Username es obligatorio.")
    if username != user.get("username"):
        if users.find_one({"username": username, "_id": {"$ne": oid}}):
            raise ValueError("Ese username ya está en uso.")
        update["username"] = username

    role = (data.get("role") or "").strip()
    if role:
        if role not in ("admin", "cajero", "entrenador", "cliente"):
            raise ValueError("Rol inválido.")
        update["role"] = role

    if "nombre" in data:
        update["nombre"] = (data.get("nombre") or "").strip() or None

    new_password = (data.get("new_password") or "").strip()
    if new_password:
        if len(new_password) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres.")
        password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        update["password"] = password_hash

    update["actualizado_en"] = datetime.utcnow()

    users.update_one({"_id": oid}, {"$set": update})

    return users.find_one({"_id": oid})


def create_entrenador(username, password, nombre=None):
    users = get_users_collection()

    existing = users.find_one({"username": username})
    if existing:
        raise ValueError("Ya existe un usuario con ese username.")

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    doc = {
        "username": username,
        "password": password_hash,
        "role": "entrenador",
        "nombre": nombre,
    }

    users.insert_one(doc)
    return doc


def update_entrenador(entrenador_id, username=None, nombre=None):
    users = get_users_collection()

    _id = ObjectId(entrenador_id)
    entrenador = users.find_one({"_id": _id, "role": "entrenador"})
    if not entrenador:
        raise ValueError("Entrenador no encontrado.")

    if username and username != entrenador.get("username"):
        if users.find_one({"username": username, "_id": {"$ne": _id}}):
            raise ValueError("Ese username ya está en uso.")

    update = {}
    if username is not None:
        update["username"] = username
    if nombre is not None:
        update["nombre"] = nombre

    if update:
        users.update_one({"_id": _id}, {"$set": update})


def list_entrenadores():
    users = get_users_collection()
    return list(users.find({"role": "entrenador"}).sort("username", 1))


def reset_password_entrenador(entrenador_id, new_password):
    users = get_users_collection()
    _id = ObjectId(entrenador_id)

    entrenador = users.find_one({"_id": _id, "role": "entrenador"})
    if not entrenador:
        raise ValueError("Entrenador no encontrado.")

    new_password = (new_password or "").strip()
    if len(new_password) < 6:
        raise ValueError("La contraseña debe tener al menos 6 caracteres.")

    password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    users.update_one({"_id": _id}, {"$set": {"password": password_hash}})


def delete_entrenador(entrenador_id):
    users = get_users_collection()
    _id = ObjectId(entrenador_id)

    entrenador = users.find_one({"_id": _id, "role": "entrenador"})
    if not entrenador:
        raise ValueError("Entrenador no encontrado.")

    users.delete_one({"_id": _id})
