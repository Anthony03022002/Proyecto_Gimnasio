from datetime import datetime, timezone
from bson import ObjectId
from flask import request, redirect, url_for, flash, render_template, abort
import json

def _as_float_form(v, min_v=None, max_v=None):
    if v is None:
        return None
    s = str(v).strip().replace(",", ".")
    if s == "":
        return None
    try:
        f = float(s)
    except ValueError:
        return None
    if min_v is not None and f < min_v:
        return None
    if max_v is not None and f > max_v:
        return None
    return f

def _build_kpi_and_chart(medidas):
    if not medidas:
        return None, None, json.dumps({"labels": [], "peso": [], "grasa": [], "musculo": []})

    latest = medidas[-1]
    prev = medidas[-2] if len(medidas) >= 2 else None

    labels = []
    peso = []
    grasa = []
    musculo = []

    for m in medidas:
        dt = m.get("fecha") or m.get("creado")
        if isinstance(dt, datetime):
            labels.append(dt.strftime("%d/%m"))
        else:
            labels.append("")
        peso.append(m.get("peso_kg"))
        grasa.append(m.get("grasa_pct"))
        musculo.append(m.get("musculo_pct"))

    return latest, prev, json.dumps({
        "labels": labels,
        "peso": peso,
        "grasa": grasa,
        "musculo": musculo
    })
