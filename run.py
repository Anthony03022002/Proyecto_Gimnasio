from app import create_app, extensions

app = create_app()

@app.context_processor
def inject_publicidad():
    db = extensions.mongo_db
    if db is None:
        return {}
    pub = db["publicidades"].find_one({"activo": True}, sort=[("creado", -1)])
    return {"publicidad_activa": pub}


if __name__ == "__main__":
    app.run(debug=True, port=3000)
