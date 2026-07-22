import os

from dotenv import load_dotenv

from langchain_ollama import ChatOllama

load_dotenv()

MODEL = os.getenv("OLLAMA_MODEL")


def get_llm():

    return ChatOllama(

        model=MODEL,

        temperature=0

    )