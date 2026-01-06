from datetime import datetime
import app.extensions as extensions

def get_clientes_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["clientes"]


def crear_o_actualizar_cliente(user_id, info):

    clientes = get_clientes_collection()

    payload = dict(info or {})

    clientes.update_one(
        {"_id": user_id},
        {"$set": payload},
        upsert=True
    )

    doc = {"_id": user_id, **payload}
    return doc
