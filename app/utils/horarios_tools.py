from datetime import datetime, timedelta, timezone
from bson import ObjectId
import traceback

def _week_id_from_date_str(fecha_key: str) -> str:
    d = datetime.strptime(fecha_key, "%Y-%m-%d").date()
    week_start = d - timedelta(days=d.weekday())  # lunes
    return week_start.isoformat()

def _clamp_slot_restante(db, week_id: str, fecha_key: str, slot_key: str):
    """
    Asegura: 0 <= cupo_restante <= cupo_maximo
    (por si se pasó por cancelaciones repetidas, errores, etc.)
    """
    semanas_col = db["horarios_dias"]

    doc = semanas_col.find_one({"_id": week_id}, {"days": 1})
    if not doc:
        return

    days = doc.get("days") or []
    for d in days:
        if d.get("date") != fecha_key:
            continue
        for s in (d.get("slots") or []):
            if s.get("key") != slot_key:
                continue
            maximo = int(s.get("cupo_maximo") or 0)
            restante = int(s.get("cupo_restante") or 0)

            if restante < 0:
                semanas_col.update_one(
                    {"_id": week_id},
                    {"$set": {"days.$[d].slots.$[s].cupo_restante": 0}},
                    array_filters=[{"d.date": fecha_key}, {"s.key": slot_key}],
                )
            elif maximo > 0 and restante > maximo:
                semanas_col.update_one(
                    {"_id": week_id},
                    {"$set": {"days.$[d].slots.$[s].cupo_restante": maximo}},
                    array_filters=[{"d.date": fecha_key}, {"s.key": slot_key}],
                )
            return
