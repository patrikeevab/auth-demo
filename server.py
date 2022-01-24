import hmac
import hashlib
import base64
import hashlib
import json
from tokenize import cookie_re
from typing import Optional
import logging
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "953bed7a20d52710a129c75181891058396963f8e5c6c9672f19afdd267f3ddc"
PASSWORD_SALT = "e67d83309302645657c48073cc1655f2098c5af042c06f687ddb0968f9164898"

def sign_data(data: str) -> str:
        """Возвращает подписанные данные data"""
        return hmac.new(
                SECRET_KEY.encode(), 
                msg=data.encode(),
                digestmod=hashlib.sha256
        ).hexdigest().upper()

def get_username_from_signed_string (username_signed: str) -> Optional[str]:
        username_base64, sign = username_signed.split(".")
        username = base64.b64decode(username_base64.encode()).decode()
        valid_sign = sign_data(username)
        if hmac.compare_digest(valid_sign, sign):
                return username

def verify_password(username: str, pasword: str) -> bool:
        password_hash = hashlib.sha256((pasword + PASSWORD_SALT).encode()).hexdigest().lower()
        stored_password_hash = users[username]['password'].lower()
        return password_hash == stored_password_hash

users = {
        "alexey@user.com": {
                "name": "Алексей",
                "password": "13d80f8355d3175c776e2ff11048817b01262b4cca6e0339f5eef6b17163cfd4",
                "balance": 100_000
        },
        "petr@user.com": {
                "name": "Петр",
                "password": "3f1872ef1131d49f2667941b83c88e3020fbabf73717993e2a9c249f3151d1e9",
                "balance": 500_000
        }
}

@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
        with open('templates/login.html', 'r') as f:
                login_page = f.read()
        if not username:
                return Response(login_page, media_type='text/html')
        valid_username = get_username_from_signed_string(username)
        if not valid_username:
                response = Response(login_page, media_type='text/html')
                response.delete_cookie(key="username")
                return response
        try:
                user = users[valid_username]
        except KeyError:
                response = Response(login_page, media_type='text/html')
                response.delete_cookie(key="username")
                return response
        return Response(f"Привет {user['name']}!<br />Баланс {user['balance']}", media_type='text/html')        

@app.post('/login')
def process_login_page(username : str = Form(...), password : str = Form(...)):
        user = users.get(username)
        if not user or not verify_password(username, password):
                #return Response("Я вас не знаю", media_type='text/html') 
                return Response(
                        json.dumps({
                                "success": False,
                                "message": "Я вас не знаю"
                        }), media_type='application/json') 
        
        response = Response(
                        json.dumps({
                                "success": True,
                                "message": f"Привет {user['name']}!<br />Баланс {user['balance']}"
                        }), media_type='application/json') 

        username_signed = base64.b64encode(username.encode()).decode() + '.' + \
                          sign_data(username)
        response.set_cookie(key="username", value=username_signed)
        return response