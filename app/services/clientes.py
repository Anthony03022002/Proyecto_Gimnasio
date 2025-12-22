import app.extensions as extensions

def get_clientes_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["clientes"]


def crear_o_actualizar_cliente(user_id, info):
    """
    user_id: ObjectId del usuario (users._id)
    info: dict con identificacion, nombre, email, telefono, etc.
    Guardará/actualizará en clientes con _id = user_id
    """
    clientes = get_clientes_collection()

    doc = {
        "_id": user_id,  # ✅ clave: mismo _id que en users y ventas
        **info
    }

    clientes.update_one(
        {"_id": user_id},
        {"$set": doc},
        upsert=True
    )

    return doc
