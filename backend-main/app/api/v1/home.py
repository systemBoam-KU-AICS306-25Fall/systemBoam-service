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

    Simplified behavior:
      - Use latest CVEs from core.cves as "news".
      - No strict date filtering, just pick the latest ones.
    """
    ensure_engine()
    # Just for display; not used for filtering
    _, _, date_str = today_window_utc()

    sql = text(
        """
        SELECT
            cve_id,
            COALESCE(NULLIF(summary, ''), cve_id) AS title
        FROM core.cves
        ORDER BY COALESCE(last_modified, published_at, updated_at, NOW()) DESC
        LIMIT :limit
        """
    )

    try:
        with engine.begin() as conn:
            rows = conn.execute(sql, {"limit": limit}).mappings().all()
    except DBAPIError:
        return TodayNewsResponse(date=date_str, items=[])

    items: List[NewsItem] = []
    for i, r in enumerate(rows, start=1):
        cve_id = r["cve_id"]
        title = r["title"] or cve_id
        items.append(
            NewsItem(
                rank=i,
                title=title,
                cve=cve_id,
                link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )

    return TodayNewsResponse(date=date_str, items=items)



# ---------- 1.2 Latest CVE Updates ----------


@router.get("/latest-updates", response_model=LatestUpdatesResponse)
def get_latest_updates(limit: int = Query(20, ge=1, le=100)):
    """
    Return the latest updated published CVEs.

    Data source:
      - core.cves

    Ordering:
      - By the most recent of (last_modified, published_at, updated_at)

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
        ORDER BY COALESCE(last_modified, published_at, updated_at, NOW()) DESC
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
      - k.kve_score                 (0..10)
      - a.activity_score            (0..10, filtered by 'window')

    Weighted total (scale roughly 0..10):
        total =
            0.60 * cvss +
            0.25 * (epss * 10.0) +
            0.10 * kve +
            0.05 * activity
    """
    ensure_engine()

    sql_full = text(
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
        ORDER BY total DESC NULLS LAST,
                 c.last_modified DESC NULLS LAST
        LIMIT :limit
        """
    )

    sql_fallback = text(
        """
        SELECT
          cve_id,
          cvss_score                                        AS cvss,
          epss_score                                        AS epss,
          0.0                                               AS kve,
          0.0                                               AS activity,
          (
            0.60*COALESCE(cvss_score, 0) +
            0.25*COALESCE(epss_score, 0)*10.0
          ) AS total
        FROM core.cves
        ORDER BY total DESC NULLS LAST,
                 COALESCE(last_modified, published_at, updated_at, NOW()) DESC
        LIMIT :limit
        """
    )

    try:
        with engine.connect() as conn:
            rows = conn.execute(sql_full, {"limit": limit, "window": window}).mappings().all()
    except DBAPIError:
        try:
            with engine.connect() as conn:
                rows = conn.execute(sql_fallback, {"limit": limit}).mappings().all()
        except DBAPIError:
            return RankingsResponse(items=[])

    items: List[RankingItem] = []
    for idx, r in enumerate(rows, start=1):
        cve_id = r["cve_id"]
        cvss = _safe_float(r.get("cvss"))
        epss = _safe_float(r.get("epss"))
        kve = _safe_float(r.get("kve"))
        activity = _safe_float(r.get("activity"))
        score = (
            0.60 * cvss
            + 0.25 * (epss * 10.0)
            + 0.10 * kve
            + 0.05 * activity
        )

        items.append(
            RankingItem(
                rank=idx,
                cve=cve_id,
                cvss=cvss,
                epss=epss,
                kve=kve,
                activity=activity,
                score=round(score, 2),
                link=f"/cve/{cve_id}",
            )
        )

    return RankingsResponse(items=items)
