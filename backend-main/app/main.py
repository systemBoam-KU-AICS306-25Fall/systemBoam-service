# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# routers
from app.api.v1 import home as home_router
from app.api.v1 import cve as cve_router

app = FastAPI(title="systemBoam API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(home_router.router)
app.include_router(cve_router.router)

@app.get("/healthz")
def healthz():
    """Liveness probe endpoint."""
    return {"ok": True}
