from langchain_ollama import ChatOllama

print("Loading model...")

llm = ChatOllama(
    model="llama3.1:8b",
    temperature=0
)

print("Sending prompt...")

response = llm.invoke("Say Hello")

print("Response received!")
print(response.content)