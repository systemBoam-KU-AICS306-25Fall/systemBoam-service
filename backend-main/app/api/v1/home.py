# app/api/v1/home.py
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, AnyHttpUrl, Field
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from zoneinfo import ZoneInfo

# DB engine import
try:
    from app.db import engine  # Adjusted to project structure
except Exception:
    engine = None  # Fallback stub for tests/dev

# Router with prefix and tags for API versioning and grouping
router = APIRouter(prefix="/api/v1/home", tags=["home"])

# ---------- Pydantic Response Models ----------


class NewsItem(BaseModel):
    rank: int
    title: str
    cve: Optional[str] = None  # single CVE id as in the spec example
    link: AnyHttpUrl


class TodayNewsResponse(BaseModel):
    date: str  # YYYY-MM-DD
    items: List[NewsItem] = Field(default_factory=list)


class LatestUpdateItem(BaseModel):
    cve: str
    summary: str
    link: str


class LatestUpdatesResponse(BaseModel):
    items: List[LatestUpdateItem] = Field(default_factory=list)


class RankingItem(BaseModel):
    rank: int
    cve: str
    cvss: float
    epss: float
    kve: float
    activity: float
    score: float
    link: str


class RankingsResponse(BaseModel):
    items: List[RankingItem] = Field(default_factory=list)


# ---------- Utils ----------

SEOUL = ZoneInfo("Asia/Seoul")


def today_window_utc() -> tuple[datetime, datetime, str]:
    """
    Compute today's time window in Asia/Seoul and convert it to UTC.

    Returns:
        tuple:
            - start_utc: UTC start datetime of today in Asia/Seoul
            - end_utc:   UTC end datetime of today in Asia/Seoul
            - date_str:  'YYYY-MM-DD' string in local (Seoul) date
    """
    now_local = datetime.now(SEOUL)
    local_start = datetime.combine(now_local.date(), time(0, 0, 0), tzinfo=SEOUL)
    local_end = local_start + timedelta(days=1)
    return (
        local_start.astimezone(timezone.utc),
        local_end.astimezone(timezone.utc),
        now_local.date().isoformat(),
    )


def ensure_engine():
    """
    Ensure SQLAlchemy engine is initialized before handling DB queries.

    Raises:
        HTTPException: if engine is not initialized.
    """
    if engine is None:
        raise HTTPException(status_code=500, detail="DB engine is not initialized.")


def _safe_float(x: Optional[object]) -> float:
    """
    Safely cast a nullable value to float, returning 0.0 if None.

    Args:
        x: Any nullable value.

    Returns:
        float: Parsed float value or 0.0 if x is None.
    """
    return float(x) if x is not None else 0.0


# ---------- 1.1 Today's CVE News ----------


@router.get("/today-news", response_model=TodayNewsResponse)
def get_today_news(limit: int = Query(10, ge=1, le=50)):
    """
    Return today's CVE-related news articles.

    Response format:
        {
          "date": "YYYY-MM-DD",
          "items": [
            {
              "rank": 1,
              "title": "...",
              "cve": "CVE-XXXX-YYYY",
              "link": "https://.../article/123"
            },
            ...
          ]
        }
    """
    ensure_engine()
    start_utc, end_utc, date_str = today_window_utc()

    sql = text(
        """
        SELECT
            title,
            url,
            COALESCE(cve_ids, ARRAY[]::text[]) AS cve_ids
        FROM core.news_articles
        WHERE published_at >= :start_utc
          AND published_at <  :end_utc
        ORDER BY score DESC NULLS LAST, published_at DESC
        LIMIT :limit
        """
    )

    items: List[NewsItem] = []
    try:
        with engine.begin() as conn:
            rows = conn.execute(
                sql, {"start_utc": start_utc, "end_utc": end_utc, "limit": limit}
            ).mappings().all()
            for i, r in enumerate(rows, start=1):
                cve_ids = list(r["cve_ids"] or [])
                first_cve = cve_ids[0] if cve_ids else None
                items.append(
                    NewsItem(
                        rank=i,
                        title=r["title"],
                        cve=first_cve,
                        link=r["url"],
                    )
                )
    except DBAPIError:
        # On DB errors (missing table, permission issues, etc.), return an empty list safely
        return TodayNewsResponse(date=date_str, items=[])

    return TodayNewsResponse(date=date_str, items=items)


# ---------- 1.2 Latest CVE Updates ----------


@router.get("/latest-updates", response_model=LatestUpdatesResponse)
def get_latest_updates(limit: int = Query(20, ge=1, le=100)):
    """
    Return the latest updated published CVEs.

    Response format:
        {
          "items": [
            {
              "cve": "CVE-XXXX-YYYY",
              "summary": "...",
              "link": "/cve/CVE-XXXX-YYYY"
            },
            ...
          ]
        }
    """
    ensure_engine()
    sql = text(
        """
        SELECT
            cve_id AS cve,
            COALESCE(NULLIF(summary, ''), '(no summary)') AS summary
        FROM core.cves
        WHERE COALESCE(state, 'PUBLISHED') = 'PUBLISHED'
        ORDER BY last_modified DESC NULLS LAST
        LIMIT :limit
        """
    )

    try:
        with engine.begin() as conn:
            rows = conn.execute(sql, {"limit": limit}).mappings().all()
    except DBAPIError:
        # On DB errors, safely return an empty result
        return LatestUpdatesResponse(items=[])

    items = [
        LatestUpdateItem(cve=r["cve"], summary=r["summary"], link=f"/cve/{r['cve']}")
        for r in rows
    ]
    return LatestUpdatesResponse(items=items)


# ---------- 1.3 CVE Rankings ----------


@router.get("/rankings", response_model=RankingsResponse)
def get_rankings(
    limit: int = Query(10, ge=1, le=100),
    window: str = "7d",  # e.g., '7d', '30d'
):
    """
    Returns top CVEs sorted by a weighted score using existing signals.

    Data sources:
      - c.cvss_score                (0..10)
      - epss from core.epss.epss    (0..1, fallback to c.epss_score)
      - k.kve_score                 (assumed 0..10)
      - a.activity_score            (assumed 0..10, filtered by 'window')

    Weighted total (linear score, not normalized to 0..100):
        total =
            0.60 * cvss +
            0.25 * (epss * 10.0) +
            0.10 * kve +
            0.05 * activity

    Response format:
        {
          "items": [
            {
              "rank": 1,
              "cve": "CVE-XXXX-YYYY",
              "cvss": 9.8,
              "epss": 0.42,
              "kve": 8.5,
              "activity": 6.0,
              "score": 8.74,
              "link": "/cve/CVE-XXXX-YYYY"
            },
            ...
          ]
        }
    """
    ensure_engine()

    # Build ranking based on a single SQL query combining scores from multiple tables.
    sql = text(
        """
        SELECT
          c.cve_id,
          c.cvss_score                                        AS cvss,
          COALESCE(e.epss, c.epss_score)                      AS epss,
          k.kve_score                                         AS kve,
          a.activity_score                                    AS activity,
          (
            0.60*COALESCE(c.cvss_score, 0) +
            0.25*COALESCE(COALESCE(e.epss, c.epss_score, 0)*10.0, 0) +
            0.10*COALESCE(k.kve_score, 0) +
            0.05*COALESCE(a.activity_score, 0)
          ) AS total
        FROM core.cves c
        LEFT JOIN core.epss     e ON e.cve_id = c.cve_id
        LEFT JOIN core.kve      k ON k.cve_id = c.cve_id
        LEFT JOIN core.activity a ON a.cve_id = c.cve_id AND a.time_window = :window
        ORDER BY total DESC NULLS LAST, c.last_modified DESC NULLS LAST
        LIMIT :limit
        """
    )

    try:
        # Use a simple connection for read-only ranking query
        with engine.connect() as conn:
            rows = conn.execute(sql, {"limit": limit, "window": window}).mappings().all()
    except DBAPIError:
        # On DB errors, return an empty ranking list
        return RankingsResponse(items=[])

    items: List[RankingItem] = []
    for idx, r in enumerate(rows, start=1):
        items.append(
            RankingItem(
                rank=idx,
                cve=r["cve_id"],
                cvss=_safe_float(r.get("cvss")),
                epss=_safe_float(r.get("epss")),
                kve=_safe_float(r.get("kve")),
                activity=_safe_float(r.get("activity")),
                score=round(_safe_float(r.get("total")), 2),
                link=f"/cve/{r['cve_id']}",
            )
        )

    return RankingsResponse(items=items)
