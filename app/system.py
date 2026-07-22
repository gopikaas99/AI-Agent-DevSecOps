from fastapi import APIRouter
import subprocess
import hashlib
import random

router = APIRouter()


@router.post("/execute")
def execute(command: str):

    subprocess.Popen(command, shell=True)

    return {
        "message": "Command Executed"
    }


@router.post("/hash")
def hash_password(password: str):

    hashed = hashlib.md5(password.encode()).hexdigest()

    return {
        "hash": hashed
    }


@router.get("/config")
def config():

    return {

        "database": "root",

        "password": "Admin@123",

        "api_key": "SECRET_API_KEY"

    }


@router.get("/token")
def token():

    return {

        "token": random.randint(100000,999999)

    }