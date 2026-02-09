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
        apellido=cliente_data.get("apellido"),
        email=cliente_data.get("email"),
        telefono=cliente_data.get("telefono"),
        fecha_nacimiento=cliente_data.get("fecha_nacimiento"),

        # ✅ NUEVOS
        nickname=cliente_data.get("nickname"),
        sexo=cliente_data.get("sexo"),
        contacto_emergencia=cliente_data.get("contacto_emergencia"),
    )

    venta_doc = {
        "cliente_id": cliente_user["_id"],     
        "vendedor": vendedor_username,
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


def _parse_date_yyyy_mm_dd(s: str):
    """
    Recibe 'YYYY-MM-DD' (input type="date") y devuelve datetime UTC.
    """
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.strip())  # naive (YYYY-MM-DD)
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def listar_ventas_por_cajero(vendedor_username, limit=20, skip=0, q=None, fecha_desde=None, fecha_hasta=None):

    ventas = get_ventas_collection()

    q = (q or "").strip()
    dt_desde = _parse_date_yyyy_mm_dd(fecha_desde)
    dt_hasta = _parse_date_yyyy_mm_dd(fecha_hasta)

    match_base = {"vendedor": vendedor_username}

    # filtro fechas (incluye todo el día "hasta")
    if dt_desde or dt_hasta:
        rango = {}
        if dt_desde:
            rango["$gte"] = dt_desde.replace(hour=0, minute=0, second=0, microsecond=0)
        if dt_hasta:
            rango["$lte"] = dt_hasta.replace(hour=23, minute=59, second=59, microsecond=999000)
        match_base["fecha"] = rango

    pipeline = [
        {"$match": match_base},

        # lookup cliente
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
    ]

    # filtro texto por cliente (nombre, apellido, identificacion)
    if q:
        pipeline.append({
            "$match": {
                "$or": [
                    {"cliente.nombre": {"$regex": q, "$options": "i"}},
                    {"cliente.apellido": {"$regex": q, "$options": "i"}},
                    {"cliente.identificacion": {"$regex": q, "$options": "i"}},
                ]
            }
        })

    pipeline += [
        {"$project": {
            "fecha": 1,
            "membresia": 1,
            "vendedor": 1,

            "cliente_nombre": {"$ifNull": ["$cliente.nombre", ""]},
            "cliente_apellido": {"$ifNull": ["$cliente.apellido", ""]},
            "cliente_identificacion": {"$ifNull": ["$cliente.identificacion", ""]},
            "cliente_telefono": {"$ifNull": ["$cliente.telefono", ""]},
        }},
        {"$sort": {"fecha": -1}},          # más reciente -> más antiguo
        {"$skip": int(skip)},              # ✅ NUEVO
        {"$limit": int(limit)},            # 20
    ]

    return list(ventas.aggregate(pipeline))


def contar_ventas_por_cajero(vendedor_username, q=None, fecha_desde=None, fecha_hasta=None):
    ventas = get_ventas_collection()

    q = (q or "").strip()
    dt_desde = _parse_date_yyyy_mm_dd(fecha_desde)
    dt_hasta = _parse_date_yyyy_mm_dd(fecha_hasta)

    match_base = {"vendedor": vendedor_username}

    if dt_desde or dt_hasta:
        rango = {}
        if dt_desde:
            rango["$gte"] = dt_desde.replace(hour=0, minute=0, second=0, microsecond=0)
        if dt_hasta:
            rango["$lte"] = dt_hasta.replace(hour=23, minute=59, second=59, microsecond=999000)
        match_base["fecha"] = rango

    pipeline = [
        {"$match": match_base},
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
    ]

    if q:
        pipeline.append({
            "$match": {
                "$or": [
                    {"cliente.nombre": {"$regex": q, "$options": "i"}},
                    {"cliente.apellido": {"$regex": q, "$options": "i"}},
                    {"cliente.identificacion": {"$regex": q, "$options": "i"}},
                ]
            }
        })

    pipeline.append({"$count": "total"})
    res = list(ventas.aggregate(pipeline))
    return res[0]["total"] if res else 0

def resumen_ventas_hoy_por_cajero(vendedor_username):
    ventas = get_ventas_collection()

    ahora = datetime.now(timezone.utc)
    inicio = ahora.replace(hour=0, minute=0, second=0, microsecond=0)
    fin = ahora.replace(hour=23, minute=59, second=59, microsecond=999000)

    conteo = ventas.count_documents({
        "vendedor": vendedor_username,                 # ✅ campo real
        "fecha": {"$gte": inicio, "$lte": fin}
    })

    return {"conteo": conteo}
