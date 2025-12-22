from functools import wraps
from flask import render_template, redirect, url_for, request, session, flash
from . import web_bp
from app.services.user_service import get_users_collection, create_cajero, list_cajeros, update_cajero, reset_password_cajero, delete_cajero
from app.extensions import bcrypt
from app.services.ventas_service import crear_venta, listar_ventas_por_cajero, resumen_ventas_hoy_por_cajero, get_ventas_collection
from datetime import date, datetime, timedelta, time, timezone
import app.extensions as extensions
from app.services.horarios_semanales import get_weekly_config, save_weekly_config, DAYS


def login_required(role=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("web.login"))
            if role and session.get("user_role") != role:
                flash("No tienes permiso para acceder a esta sección.", "danger")
                return redirect(url_for(f"web.{session.get('user_role')}_dashboard"))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


@web_bp.get("/")
def home():
    if "user_role" in session:
        return redirect(url_for(f"web.{session['user_role']}_dashboard"))
    return redirect(url_for("web.login"))


@web_bp.get("/login")
def login():
    return render_template("auth_login.html")


@web_bp.post("/login")
def login_post():
    username = request.form.get("username")
    password = request.form.get("password")

    user = get_users_collection().find_one({"username": username})

    if not user:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for("web.login"))

    if not bcrypt.check_password_hash(user["password"], password):
        flash("Contraseña incorrecta", "danger")
        return redirect(url_for("web.login"))

    # Guardar sesión
    session["username"] = user["username"]
    session["user_role"] = user["role"]

    # Redirigir según rol
    return redirect(url_for(f"web.{user['role']}_dashboard"))


@web_bp.get("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for("web.login"))


# Administrador

@web_bp.get("/admin")
@login_required(role="admin")
def admin_dashboard():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    users = db["users"]
    clientes = db["clientes"]
    ventas = db["ventas"]

    # Contadores
    total_clientes = clientes.count_documents({})
    total_entrenadores = users.count_documents({"role": "entrenador"})
    total_cajeros = users.count_documents({"role": "cajero"})

    # Ventas de hoy (UTC, consistente con tus ISODate)
    ahora = datetime.now(timezone.utc)
    inicio = ahora.replace(hour=0, minute=0, second=0, microsecond=0)
    fin = ahora.replace(hour=23, minute=59, second=59, microsecond=999000)

    ventas_hoy = ventas.count_documents({"fecha": {"$gte": inicio, "$lte": fin}})

    # Tabla: últimas ventas con datos del cliente (lookup)
    pipeline = [
        {"$sort": {"fecha": -1}},
        {"$limit": 10},
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "fecha": 1,
            "vendedor_username": 1,
            "membresia": 1,
            "cliente_nombre": "$cliente.nombre",
            "cliente_identificacion": "$cliente.identificacion",
        }},
    ]
    ultimas_ventas = list(ventas.aggregate(pipeline))

    return render_template(
        "dashboard_admin.html",
        total_clientes=total_clientes,
        total_entrenadores=total_entrenadores,
        total_cajeros=total_cajeros,
        ventas_hoy=ventas_hoy,
        ultimas_ventas=ultimas_ventas,
    )



# Cajeros
@web_bp.get("/admin/cajeros")
@login_required(role="admin")
def admin_cajeros():
    cajeros = list_cajeros()
    return render_template("admin_cajeros.html", cajeros=cajeros)


@web_bp.post("/admin/cajeros")
@login_required(role="admin")
def admin_cajeros_post():
    username = request.form.get("username")
    nombre = request.form.get("nombre")
    password = request.form.get("password")

    if not username or not password:
        flash("Usuario y contraseña son obligatorios.", "danger")
        return redirect(url_for("web.admin_cajeros"))

    try:
        create_cajero(username=username, password=password, nombre=nombre)
        flash(f"Cajero '{username}' creado correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))

# EDITAR CAJERO

@web_bp.post("/admin/cajeros/<cajero_id>/edit")
@login_required(role="admin")
def admin_cajeros_edit(cajero_id):
    username = request.form.get("username")
    nombre = request.form.get("nombre")

    try:
        update_cajero(cajero_id, username=username, nombre=nombre)
        flash("Cajero actualizado.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))

# RESET PASSWORD CAJERO
@web_bp.post("/admin/cajeros/<cajero_id>/reset-password")
@login_required(role="admin")
def admin_cajeros_reset_password(cajero_id):
    new_password = request.form.get("new_password")
    if not new_password:
        flash("La nueva contraseña es obligatoria.", "danger")
        return redirect(url_for("web.admin_cajeros"))

    try:
        reset_password_cajero(cajero_id, new_password)
        flash("Contraseña actualizada.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))


# ELIMINAR CAJERO

@web_bp.post("/admin/cajeros/<cajero_id>/delete")
@login_required(role="admin")
def admin_cajeros_delete(cajero_id):
    try:
        delete_cajero(cajero_id)
        flash("Cajero eliminado.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))


@web_bp.get("/cajero")
@login_required(role="cajero")
def cajero_dashboard():
    username = session.get("username")

    ventas = listar_ventas_por_cajero(username, limit=10)
    resumen_hoy = resumen_ventas_hoy_por_cajero(username)
    ultima_venta = ventas[0] if ventas else None

    return render_template(
        "dashboard_cajero.html",
        ventas=ventas,
        resumen_hoy=resumen_hoy,
        ultima_venta=ultima_venta,
    )




# Entrenador

@web_bp.get("/entrenador")
@login_required(role="entrenador")
def entrenador_dashboard():
    return render_template("dashboard_entrenador.html")


# Cliente

@web_bp.get("/cliente")
@login_required(role="cliente")
def cliente_dashboard():
    return render_template("dashboard_cliente.html")


# Venta

@web_bp.get("/admin/facturacion/nueva")
@login_required()  
def facturacion_nueva():
    return render_template("facturacion.html")


@web_bp.post("/admin/facturacion/nueva")
@login_required()
def facturacion_nueva_post():
    identificacion = request.form.get("identificacion")
    nombre = request.form.get("nombre")
    email = request.form.get("email") or None
    telefono = request.form.get("telefono") or None

    meses_raw = request.form.get("meses") or "1"
    fecha_desde_raw = request.form.get("fecha_desde")
    fecha_hasta_raw = request.form.get("fecha_hasta")

    if not identificacion or not nombre:
        flash("Identificación y nombre del cliente son obligatorios.", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    # validar meses
    try:
        meses = int(meses_raw)
        if meses < 1 or meses > 12:
            raise ValueError()
    except ValueError:
        flash("Meses inválidos (debe ser 1 a 12).", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    # parse fecha_desde (date)
    try:
        if fecha_desde_raw:
            fecha_desde_date = datetime.strptime(fecha_desde_raw, "%Y-%m-%d").date()
        else:
            fecha_desde_date = date.today()
    except ValueError:
        flash("Fecha desde inválida.", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    # parse/calcular fecha_hasta (date)
    try:
        if fecha_hasta_raw:
            fecha_hasta_date = datetime.strptime(fecha_hasta_raw, "%Y-%m-%d").date()
        else:
            fecha_hasta_date = fecha_desde_date + timedelta(days=meses * 30)
    except ValueError:
        flash("Fecha hasta inválida.", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    # ✅ convertir a datetime (Mongo => ISODate)
    fecha_desde_dt = datetime.combine(fecha_desde_date, time.min)
    fecha_hasta_dt = datetime.combine(fecha_hasta_date, time.min)

    cliente_data = {
        "identificacion": identificacion,
        "nombre": nombre,
        "email": email,
        "telefono": telefono,
    }

    # ✅ ya no mandamos items (evitamos redundancia)
    membresia = {
        "tipo": "membresia",
        "meses": meses,
        "fecha_desde": fecha_desde_dt,  # datetime -> ISODate
        "fecha_hasta": fecha_hasta_dt,  # datetime -> ISODate
    }

    vendedor_username = session.get("username")

    # ✅ ahora crear_venta recibe membresia, no items
    venta = crear_venta(cliente_data, membresia, vendedor_username)

    return render_template(
        "venta_lista.html",
        venta=venta,
        credenciales={
            "username": venta.get("cliente_username"),
            "password": venta.get("_generated_password"),
        }
    )



# Horarios 

# @web_bp.get("/admin/horarios")
# @login_required(role="admin")
# def admin_horarios():
#     today = date.today().isoformat()
#     return render_template("admin_horarios.html", today=today)


# @web_bp.post("/admin/horarios")
# @login_required(role="admin")
# def admin_horarios_post():
#     fecha_raw = request.form.get("fecha")  # YYYY-MM-DD
#     cupo_maximo = request.form.get("cupo_maximo") or "10"
#     slot_minutes = request.form.get("slot_minutes") or "60"

#     # Bloques (por ahora 2)
#     b1_ini = request.form.get("b1_ini") or "05:00"
#     b1_fin = request.form.get("b1_fin") or "12:00"
#     b2_ini = request.form.get("b2_ini") or "15:00"
#     b2_fin = request.form.get("b2_fin") or "22:00"

#     if not fecha_raw:
#         flash("La fecha es obligatoria.", "danger")
#         return redirect(url_for("web.admin_horarios"))

#     try:
#         d = datetime.strptime(fecha_raw, "%Y-%m-%d").date()
#         fecha_day_utc = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=timezone.utc)
#         cupo_maximo = int(cupo_maximo)
#         slot_minutes = int(slot_minutes)
#         if cupo_maximo < 1:
#             raise ValueError()
#         if slot_minutes not in (30, 60):
#             # para empezar simple
#             raise ValueError()
#     except ValueError:
#         flash("Datos inválidos (cupo o intervalo).", "danger")
#         return redirect(url_for("web.admin_horarios"))

#     bloques = [(b1_ini, b1_fin), (b2_ini, b2_fin)]
#     creado_por = session.get("username")

#     res = crear_slots_para_fecha(
#         fecha_day_utc=fecha_day_utc,
#         bloques=bloques,
#         slot_minutes=slot_minutes,
#         cupo_maximo=cupo_maximo,
#         creado_por=creado_por,
#     )

#     flash(f"Slots creados: {res['created']}. Duplicados omitidos: {res['skipped']}.", "success")
#     return redirect(url_for("web.horarios_publico", fecha=fecha_raw))


@web_bp.get("/horarios")
@login_required()
def horarios_publico():
    fecha_raw = request.args.get("fecha")
    d = datetime.strptime(fecha_raw, "%Y-%m-%d").date() if fecha_raw else date.today()

    cfg = get_weekly_config()
    weekday_map = {0:"mon",1:"tue",2:"wed",3:"thu",4:"fri",5:"sat",6:"sun"}
    day_key = weekday_map[d.weekday()]

    day_cfg = (cfg.get("days") or {}).get(day_key, {"enabled": False, "bloques": []})

    return render_template(
        "horarios_publico.html",
        fecha=d,
        cfg=cfg,
        day_cfg=day_cfg,
    )


@web_bp.get("/admin/horarios-semana")
@login_required(role="admin")
def admin_horarios_semana():
    cfg = get_weekly_config()
    return render_template("admin_horarios.html", cfg=cfg)


@web_bp.post("/admin/horarios-semana")
@login_required(role="admin")
def admin_horarios_semana_post():
    slot_minutes = request.form.get("slot_minutes") or "60"
    cupo_maximo = request.form.get("cupo_maximo") or "10"

    try:
        slot_minutes = int(slot_minutes)
        cupo_maximo = int(cupo_maximo)
        if slot_minutes not in (30, 60): raise ValueError()
        if cupo_maximo < 1: raise ValueError()
    except ValueError:
        flash("Intervalo o cupo inválido.", "danger")
        return redirect(url_for("web.admin_horarios_semana"))

    days_dict = {}
    for k in DAYS:
        enabled = request.form.get(f"day_enabled_{k}") is not None

        bloques = []
        if enabled:
            b1_ini = (request.form.get(f"{k}_b1_ini") or "").strip()
            b1_fin = (request.form.get(f"{k}_b1_fin") or "").strip()
            b2_ini = (request.form.get(f"{k}_b2_ini") or "").strip()
            b2_fin = (request.form.get(f"{k}_b2_fin") or "").strip()

            # agrega solo bloques completos
            if b1_ini and b1_fin:
                bloques.append({"ini": b1_ini, "fin": b1_fin})
            if b2_ini and b2_fin:
                bloques.append({"ini": b2_ini, "fin": b2_fin})

        days_dict[k] = {"enabled": enabled, "bloques": bloques}

    save_weekly_config(slot_minutes, cupo_maximo, days_dict)
    flash("Configuración semanal guardada.", "success")
    return redirect(url_for("web.horarios_publico"))
