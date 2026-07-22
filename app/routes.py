from fastapi import APIRouter
from app.calculator import Calculator

router = APIRouter()

calc = Calculator()


@router.get("/add")
def add(a: float, b: float):
    return {"result": calc.add(a, b)}


@router.get("/subtract")
def subtract(a: float, b: float):
    return {"result": calc.subtract(a, b)}


@router.get("/multiply")
def multiply(a: float, b: float):
    return {"result": calc.multiply(a, b)}


@router.get("/divide")
def divide(a: float, b: float):
    return {"result": calc.divide(a, b)}