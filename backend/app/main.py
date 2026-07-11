from fastapi import FastAPI

app = FastAPI(
    title="InsiderGuard AI",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "project": "InsiderGuard AI",
        "status": "running"
    }