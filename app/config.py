import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_session_key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_jwt_secret")
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "horarios_db")
    DEBUG = True
