# app/api/v1/search.py
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

# DB engine import
try:
    from app.db import engine
except Exception:
    engine = None


router = APIRouter(prefix="/api/v1", tags=["search"])


class SearchItem(BaseModel):
    """One search result entry."""
    cve: str
    summary: str
    link: str


class SearchResponse(BaseModel):
    """Search response model."""
    results: List[SearchItem] = Field(default_factory=list)


def ensure_engine():
    """Ensure SQLAlchemy engine is initialized before handling DB queries."""
    if engine is None:
        raise HTTPException(status_code=500, detail="DB engine is not initialized.")


def _normalize_cve(q: str) -> str:
    """Normalize a CVE-like string (strip and uppercase)."""
    return q.strip().upper()


@router.get("/search", response_model=SearchResponse)
def search(
    q: str = Query(..., min_length=1, description="CVE ID or keyword"),
    type_: Optional[str] = Query(
        None,
        alias="type",
        pattern="^(cve|keyword)$",
        description="Search mode: 'cve' or 'keyword'. If omitted, auto-detected.",
    ),
    limit: int = Query(20, ge=1, le=100),
):
    """
    Search for CVEs by ID or keyword.

    Behavior:
        - type='cve'      → exact match on cve_id.
        - type='keyword'  → ILIKE search on cve_id and summary.
        - type is None    → automatically treated as 'cve' if q looks like 'CVE-YYYY-NNNN',
                            otherwise 'keyword'.
    """
    ensure_engine()

    mode = type_
    q_norm = _normalize_cve(q)

    # Auto-detect mode if not explicitly provided
    if mode is None:
        if q_norm.startswith("CVE-"):
            mode = "cve"
        else:
            mode = "keyword"

    try:
        with engine.begin() as conn:
            if mode == "cve":
                sql = text(
                    """
                    SELECT
                        cve_id,
                        COALESCE(NULLIF(summary, ''), '(no summary)') AS summary
                    FROM core.cves
                    WHERE cve_id = :cve_id
                    ORDER BY last_modified DESC NULLS LAST
                    LIMIT :limit
                    """
                )
                rows = conn.execute(
                    sql,
                    {"cve_id": q_norm, "limit": limit},
                ).mappings().all()
            else:
                # keyword search
                sql = text(
                    """
                    SELECT
                        cve_id,
                        COALESCE(NULLIF(summary, ''), '(no summary)') AS summary
                    FROM core.cves
                    WHERE cve_id ILIKE :pattern
                       OR summary ILIKE :pattern
                    ORDER BY last_modified DESC NULLS LAST
                    LIMIT :limit
                    """
                )
                rows = conn.execute(
                    sql,
                    {"pattern": f"%{q}%", "limit": limit},
                ).mappings().all()
    except DBAPIError:
        return SearchResponse(results=[])

    results: List[SearchItem] = [
        SearchItem(
            cve=row["cve_id"],
            summary=row["summary"],
            link=f"/cve/{row['cve_id']}",
        )
        for row in rows
    ]
    return SearchResponse(results=results)
