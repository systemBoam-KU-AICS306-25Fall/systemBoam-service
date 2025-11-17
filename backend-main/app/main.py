# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import home as home_router
from app.api.v1 import cve as cve_router
from app.api.v1 import uploads as uploads_router
from app.api.v1 import search as search_router

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
app.include_router(uploads_router.router)
app.include_router(search_router.router)


@app.get("/healthz")
def healthz():
    """Liveness probe endpoint."""
    return {"ok": True}
