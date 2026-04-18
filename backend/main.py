from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def root():
    return {"message": "Hello from Cyber Co-Pilot API"}


@app.get("/health")
def health():
    return {"status": "ok"}
