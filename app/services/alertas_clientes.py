from datetime import datetime, timezone
from zoneinfo import ZoneInfo

def obtener_clientes_por_vencer(db, dias_objetivo=(2, 1, 0), limitar=50):

    ventas_col = db["ventas"]
    clientes_col = db["clientes"]

    TZ_EC = ZoneInfo("America/Guayaquil")
    hoy_ec = datetime.now(timezone.utc).astimezone(TZ_EC).date()

    pipeline = [
        {"$sort": {"fecha": -1}},  
        {"$group": {
            "_id": "$cliente_id",
            "venta": {"$first": "$$ROOT"}
        }},
        {"$limit": int(limitar)},
    ]

    ultimas = list(ventas_col.aggregate(pipeline))

    ids = []
    tmp = {}  

    for row in ultimas:
        cliente_id = row["_id"]
        venta = row.get("venta") or {}
        membresia = (venta.get("membresia") or {})
        fh = membresia.get("fecha_hasta")

        if not fh:
            continue

        if isinstance(fh, datetime) and fh.tzinfo is None:
            fh = fh.replace(tzinfo=timezone.utc)

        try:
            fh_ec = fh.astimezone(TZ_EC).date()
        except Exception:
            continue

        dias_restantes = (fh_ec - hoy_ec).days  

        no_renovo = (dias_restantes < 0)

        if (dias_restantes in dias_objetivo) or no_renovo:
            ids.append(cliente_id)
            tmp[cliente_id] = {
                "dias_restantes": int(dias_restantes),
                "fecha_hasta": fh_ec.isoformat(),
                "no_renovo": bool(no_renovo),
            }

    if not ids:
        return []

    clientes = list(clientes_col.find(
        {"_id": {"$in": ids}},
        {"nombre": 1, "apellido": 1, "telefono": 1, "email": 1, "identificacion": 1, "activo": 1}
    ))

    out = []
    for c in clientes:
        cid = c["_id"]
        calc = tmp.get(cid, {})
        nombre = f"{c.get('nombre','')} {c.get('apellido','')}".strip() or "-"
        out.append({
            "_id": str(cid),
            "nombre": nombre,
            "identificacion": c.get("identificacion",""),
            "telefono": c.get("telefono",""),
            "email": c.get("email",""),
            "activo": bool(c.get("activo", True)),
            "dias_restantes": calc.get("dias_restantes"),
            "fecha_hasta": calc.get("fecha_hasta"),
            "no_renovo": calc.get("no_renovo"),
        })

    out.sort(key=lambda x: (x["dias_restantes"], x["nombre"]))
    return out
