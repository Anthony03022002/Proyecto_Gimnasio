from datetime import datetime, date, time, timedelta
from zoneinfo import ZoneInfo

from app.services.horarios_semanales import resolver_bloques_del_dia

TZ_EC = ZoneInfo("America/Guayaquil")

def _hhmm_to_time(hhmm: str) -> time:
    h, m = hhmm.split(":")
    return time(int(h), int(m))

def _to_local_dt(d: date, t: time) -> datetime:
    return datetime(d.year, d.month, d.day, t.hour, t.minute, tzinfo=TZ_EC)

def _get_blocks_for_date(cfg: dict, wd_date: date, weekday_map: dict):
    day_key = weekday_map[wd_date.weekday()]
    day_cfg = (cfg.get("dias") or {}).get(day_key, {})
    if not day_cfg.get("activo"):
        return None, None

    bloques = resolver_bloques_del_dia(day_cfg) or []  
    if not bloques:
        return None, None

    def pick(b):
        ini = b.get("ini") or b.get("inicio")
        fin = b.get("fin")
        if not ini or not fin:
            return None
        return (_hhmm_to_time(ini), _hhmm_to_time(fin))

    b1 = pick(bloques[0]) if len(bloques) >= 1 else None
    b2 = pick(bloques[1]) if len(bloques) >= 2 else None
    return b1, b2

def _slot_block_num(slot_start: datetime, b1, b2):
    if slot_start.tzinfo is None:
        slot_start = slot_start.replace(tzinfo=TZ_EC)

    t = slot_start.timetz().replace(tzinfo=None)
    if b1 and (b1[0] <= t < b1[1]):
        return 1
    if b2 and (b2[0] <= t < b2[1]):
        return 2
    return None

def _open_time_for_block(cfg, slot_date: date, block_num: int, weekday_map: dict):
    base_day = slot_date - timedelta(days=1)

    if slot_date.weekday() == 0:  
        base_day = slot_date - timedelta(days=2)  

    if block_num == 1:
        return _to_local_dt(base_day, time(12, 0))
    if block_num == 2:
        return _to_local_dt(base_day, time(20, 0))

    return None

def _turno_permite(turno_cliente: str, block_num: int) -> bool:
    if turno_cliente == "full":
        return True
    if turno_cliente == "manana":
        return block_num == 1
    if turno_cliente == "tarde":
        return block_num == 2
    return False
