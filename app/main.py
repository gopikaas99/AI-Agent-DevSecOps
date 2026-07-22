from fastapi import FastAPI

from app.routes import router as calculator_router
from app.auth import router as auth_router
from app.system import router as system_router

app = FastAPI(
    title="AI Agent DevSecOps Calculator API",
    version="1.0.0",
)

app.include_router(calculator_router)
app.include_router(auth_router)
app.include_router(system_router)


@app.get("/")
def home():
    return {
        "message": "Welcome to the AI Agent DevSecOps Calculator API"
    }