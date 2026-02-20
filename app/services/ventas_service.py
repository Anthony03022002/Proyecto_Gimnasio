from datetime import datetime, timezone
import app.extensions as extensions
from .user_service import find_or_create_cliente
from zoneinfo import ZoneInfo

TZ_EC = ZoneInfo("America/Guayaquil")


def get_ventas_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["ventas"]


def _utc_bounds_from_ec_date_str(s: str, end_of_day: bool):
    """
    Convierte un YYYY-MM-DD (día Ecuador) a límite UTC para consultar el campo 'fecha' (UTC).
    """
    if not s:
        return None
    try:
        d = datetime.strptime(s.strip(), "%Y-%m-%d").date()
        if end_of_day:
            dt_ec = datetime(d.year, d.month, d.day, 23, 59, 59, 999000, tzinfo=TZ_EC)
        else:
            dt_ec = datetime(d.year, d.month, d.day, 0, 0, 0, 0, tzinfo=TZ_EC)
        return dt_ec.astimezone(timezone.utc)
    except Exception:
        return None


def _to_ec_datetime(value):
    """
    Normaliza 'fecha' a datetime en Ecuador para UI.
    Mongo normalmente devuelve datetime naive (asumir UTC).
    """
    if not value:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)
        return value.astimezone(TZ_EC)
    return None


def crear_venta(cliente_data, membresia, vendedor_username):
    ventas = get_ventas_collection()

    cliente_user, password_plain = find_or_create_cliente(
        identificacion=cliente_data["identificacion"],
        nombre=cliente_data["nombre"],
        apellido=cliente_data.get("apellido"),
        email=cliente_data.get("email"),
        telefono=cliente_data.get("telefono"),
        fecha_nacimiento=cliente_data.get("fecha_nacimiento"),
        nickname=cliente_data.get("nickname"),
        sexo=cliente_data.get("sexo"),
        contacto_emergencia=cliente_data.get("contacto_emergencia"),
    )

    # ✅ Fecha/hora actual real (instante) en UTC -> ISODate en Mongo
    ahora_utc = datetime.now(timezone.utc)

    venta_doc = {
        "cliente_id": cliente_user["_id"],
        "vendedor": vendedor_username,
        "fecha": ahora_utc,  # ✅ NO string, SÍ datetime

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

    # opcional UI: fecha en Ecuador lista
    f_ec = _to_ec_datetime(venta_doc.get("fecha"))
    venta_doc["fecha_ec_txt"] = f_ec.strftime("%d/%m/%Y %H:%M") if f_ec else ""

    return venta_doc


def listar_ventas_por_cajero(vendedor_username, limit=20, skip=0, q=None, fecha_desde=None, fecha_hasta=None):
    ventas = get_ventas_collection()

    q = (q or "").strip()

    dt_desde_utc = _utc_bounds_from_ec_date_str(fecha_desde, end_of_day=False)
    dt_hasta_utc = _utc_bounds_from_ec_date_str(fecha_hasta, end_of_day=True)

    match_base = {"vendedor": vendedor_username}

    if dt_desde_utc or dt_hasta_utc:
        rango = {}
        if dt_desde_utc:
            rango["$gte"] = dt_desde_utc
        if dt_hasta_utc:
            rango["$lte"] = dt_hasta_utc
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
        {"$sort": {"fecha": -1}},
        {"$skip": int(skip)},
        {"$limit": int(limit)},
    ]

    rows = list(ventas.aggregate(pipeline))

    # ✅ para mostrar en Ecuador sin romper Jinja
    for r in rows:
        f_ec = _to_ec_datetime(r.get("fecha"))
        r["fecha_ec_txt"] = f_ec.strftime("%d/%m/%Y %H:%M") if f_ec else ""

    return rows


def contar_ventas_por_cajero(vendedor_username, q=None, fecha_desde=None, fecha_hasta=None):
    ventas = get_ventas_collection()

    q = (q or "").strip()

    dt_desde_utc = _utc_bounds_from_ec_date_str(fecha_desde, end_of_day=False)
    dt_hasta_utc = _utc_bounds_from_ec_date_str(fecha_hasta, end_of_day=True)

    match_base = {"vendedor": vendedor_username}

    if dt_desde_utc or dt_hasta_utc:
        rango = {}
        if dt_desde_utc:
            rango["$gte"] = dt_desde_utc
        if dt_hasta_utc:
            rango["$lte"] = dt_hasta_utc
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

    hoy_ec = datetime.now(TZ_EC).date()
    inicio_ec = datetime(hoy_ec.year, hoy_ec.month, hoy_ec.day, 0, 0, 0, 0, tzinfo=TZ_EC)
    fin_ec = datetime(hoy_ec.year, hoy_ec.month, hoy_ec.day, 23, 59, 59, 999000, tzinfo=TZ_EC)

    inicio_utc = inicio_ec.astimezone(timezone.utc)
    fin_utc = fin_ec.astimezone(timezone.utc)

    return {
        "conteo": ventas.count_documents({
            "vendedor": vendedor_username,
            "fecha": {"$gte": inicio_utc, "$lte": fin_utc}
        })
    }