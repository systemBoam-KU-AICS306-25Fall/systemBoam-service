# app/core/config.py
from functools import lru_cache
from urllib.parse import quote_plus
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # RDS info.
    DB_HOST: str = "systemboam.ctk4e4gqsons.ap-southeast-2.rds.amazonaws.com"
    DB_PORT: int = 5432
    DB_USER: str = "appuser"
    DB_PASSWORD: str = "hmsjeremiah"
    DB_NAME: str = "collectdb"
    DB_SCHEMA: str = "core"
    DB_SSLMODE: str = "require"

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = ["*"]

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """
        Using psycopg driver.
        - sslmode=require: Enforces RDS TLS
        - options=-csearch_path=core: Sets default schema to core
          (URL encoding: '=' → %3D)
        """
        pwd = quote_plus(self.DB_PASSWORD)
        return (
            "postgresql+psycopg://"
            f"{self.DB_USER}:{pwd}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
            f"?sslmode={self.DB_SSLMODE}&options=-csearch_path%3D{self.DB_SCHEMA}"
        )

    @property
    def SQLALCHEMY_ENGINE_OPTIONS(self) -> dict:
        """
        Connection stability/pool settings (adjust if needed).
        """
        return {
            "pool_pre_ping": True,
            "pool_size": 5,
            "max_overflow": 10,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
