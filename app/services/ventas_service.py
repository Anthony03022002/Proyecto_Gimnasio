from datetime import datetime
import app.extensions as extensions
from .user_service import find_or_create_cliente
from datetime import datetime, timezone


def get_ventas_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["ventas"]


def crear_venta(cliente_data, membresia, vendedor_username):
    ventas = get_ventas_collection()

    cliente_user, password_plain = find_or_create_cliente(
        identificacion=cliente_data["identificacion"],
        nombre=cliente_data["nombre"],
        email=cliente_data.get("email"),
        telefono=cliente_data.get("telefono"),
    )

    venta_doc = {
        "cliente_id": cliente_user["_id"],     
        "vendedor_username": vendedor_username,
        "fecha": datetime.now(timezone.utc),
        "membresia": {
            "meses": membresia.get("meses"),
            "fecha_desde": membresia.get("fecha_desde"),
            "fecha_hasta": membresia.get("fecha_hasta"),
        },
    }

    result = ventas.insert_one(venta_doc)
    venta_doc["_id"] = result.inserted_id

    # solo UI
    venta_doc["cliente_username"] = cliente_user.get("username")
    venta_doc["_generated_password"] = password_plain

    return venta_doc


def listar_ventas_por_cajero(vendedor_username, limit=10):
    ventas = get_ventas_collection()

    pipeline = [
        {"$match": {"vendedor_username": vendedor_username}},
        {"$sort": {"fecha": -1}},
        {"$limit": limit},
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "fecha": 1,
            "membresia": 1,
            "vendedor_username": 1,
            "cliente_nombre": "$cliente.nombre",
            "cliente_identificacion": "$cliente.identificacion",
        }}
    ]

    return list(ventas.aggregate(pipeline))



def resumen_ventas_hoy_por_cajero(vendedor_username):
    ventas = get_ventas_collection()

    ahora = datetime.now(timezone.utc)

    inicio = ahora.replace(hour=0, minute=0, second=0, microsecond=0)
    fin = ahora.replace(hour=23, minute=59, second=59, microsecond=999000)

    cursor = ventas.find({
        "vendedor_username": vendedor_username,
        "fecha": {"$gte": inicio, "$lte": fin}
    })

    conteo = 0
    for _ in cursor:
        conteo += 1

    return {
        "conteo": conteo
    }