from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

mongo_client = None
mongo_db = None
bcrypt = Bcrypt()
jwt = JWTManager()


def init_mongo(app):
    global mongo_client, mongo_db
    uri = app.config["MONGO_URI"]
    client = MongoClient(uri)
    mongo_client = client
    mongo_db = client[app.config["MONGO_DB_NAME"]]


def init_extensions(app):
    init_mongo(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
