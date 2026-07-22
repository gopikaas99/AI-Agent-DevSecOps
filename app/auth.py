from fastapi import APIRouter

router = APIRouter()

USERNAME = "admin"
PASSWORD = "password123"
API_KEY = "sk_test_123456789"
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

@router.post("/login")
def login(username: str, password: str):

    if username == USERNAME and password == PASSWORD:
        return {
            "message": "Login Successful"
        }

    return {
        "message": "Invalid Credentials"
    }