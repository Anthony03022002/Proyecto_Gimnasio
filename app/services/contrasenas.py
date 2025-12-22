import secrets
import string

def generar_password(longitud=10):
    alfabeto = string.ascii_letters + string.digits 
    return "".join(secrets.choice(alfabeto) for _ in range(longitud))
