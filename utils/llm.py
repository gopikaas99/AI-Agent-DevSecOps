import os

from langchain_ollama import ChatOllama


def get_llm():

    model_name = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    return ChatOllama(
        model=model_name,
        temperature=0
    )