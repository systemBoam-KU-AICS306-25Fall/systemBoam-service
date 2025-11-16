# app/db.py
from sqlalchemy import create_engine
from app.core.config import get_settings

settings = get_settings()
engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URI,
    **settings.SQLALCHEMY_ENGINE_OPTIONS
)
