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
    from app.db import engine  # 프로젝트 구조에 맞춘 위치
except Exception:
    engine = None  # 테스트/임시 스텁

router = APIRouter()

# ---------- Pydantic Response Models ----------

class NewsItem(BaseModel):
    rank: int
    title: str
    link: AnyHttpUrl
    cves: List[str] = Field(default_factory=list)

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
    now_local = datetime.now(SEOUL)
    local_start = datetime.combine(now_local.date(), time(0, 0, 0), tzinfo=SEOUL)
    local_end = local_start + timedelta(days=1)
    return (
        local_start.astimezone(timezone.utc),
        local_end.astimezone(timezone.utc),
        now_local.date().isoformat(),
    )

def ensure_engine():
    if engine is None:
        raise HTTPException(status_code=500, detail="DB engine is not initialized.")

def _safe_float(x: Optional[object]) -> float:
    return float(x) if x is not None else 0.0

# ---------- 1.1 Today's CVE News ----------

@router.get("/today-news", response_model=TodayNewsResponse)
def get_today_news(limit: int = Query(10, ge=1, le=50)):
    """
    Returns: { date: 'YYYY-MM-DD', items: [{rank,title,link,cves[]}] }
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
                items.append(
                    NewsItem(
                        rank=i,
                        title=r["title"],
                        link=r["url"],
                        cves=list(r["cve_ids"] or []),
                    )
                )
    except DBAPIError as e:
        # 테이블 부재/권한 문제 시에도 빈 목록 반환
        return TodayNewsResponse(date=date_str, items=[])

    return TodayNewsResponse(date=date_str, items=items)

# ---------- 1.2 Latest CVE Updates ----------

@router.get("/latest-updates", response_model=LatestUpdatesResponse)
def get_latest_updates(limit: int = Query(20, ge=1, le=100)):
    """
    Returns: { items: [{cve, summary, link}] }
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
    except DBAPIError as e:
        # 안전하게 빈 목록 반환
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
    window: str = Query("7d"),           # e.g., '7d', '30d'
    kev_mode: str = Query("auto"),       # kept for future behavior switch: 'auto'|'kev'|'kve'
):
    """
    Returns: { items: [{rank,cve,cvss,epss,kve,activity,score,link}] }
    Notes:
      - cvss: 0~10 (as-is)
      - epss: 0~1 in DB → scaled to 0~10 (one decimal)
      - kve:  0~10; if only kev_flag exists, emulate 10/0
      - activity: assume 0~10 scale
      - score: internal weighted score for ordering (0~100)
    """
    ensure_engine()

    # Simple aggregation; USING 대신 명시적 조인으로 안정성 확보
    sql = text(
        """
        WITH base AS (
            SELECT
                c.cve_id,
                COALESCE(c.cvss_v31_score, 0)::float AS cvss,
                COALESCE(ROUND(COALESCE(e.epss, 0) * 10.0, 1), 0)::float AS epss,
                COALESCE(k.kve_score,
                         CASE WHEN kv.kev_flag THEN 10.0 ELSE 0.0 END,
                         0)::float AS kve,
                COALESCE(a.activity_score, 0)::float AS activity
            FROM core.cves c
            LEFT JOIN core.epss     e  ON e.cve_id  = c.cve_id
            LEFT JOIN core.kve      k  ON k.cve_id  = c.cve_id
            LEFT JOIN core.kev      kv ON kv.cve_id = c.cve_id
            LEFT JOIN core.activity a  ON a.cve_id  = c.cve_id AND a.time_window = :window
            WHERE COALESCE(c.state, 'PUBLISHED') = 'PUBLISHED'
        ),
        scored AS (
            SELECT
                cve_id, cvss, epss, kve, activity,
                (0.30*(cvss/10.0) + 0.40*(epss/10.0) + 0.20*(kve/10.0) + 0.10*(activity/10.0)) * 100.0
                AS score
            FROM base
        )
        SELECT cve_id, cvss, epss, kve, activity, score
        FROM scored
        ORDER BY score DESC NULLS LAST, kve DESC, cve_id ASC
        LIMIT :limit
        """
    )

    try:
        with engine.begin() as conn:
            rows = conn.execute(sql, {"limit": limit, "window": window}).mappings().all()
    except DBAPIError as e:
        return RankingsResponse(items=[])

    items: List[RankingItem] = []
    for i, r in enumerate(rows, start=1):
        items.append(
            RankingItem(
                rank=i,
                cve=r["cve_id"],
                cvss=_safe_float(r.get("cvss")),
                epss=_safe_float(r.get("epss")),
                kve=_safe_float(r.get("kve")),
                activity=_safe_float(r.get("activity")),
                score=_safe_float(r.get("score")),
                link=f"/cve/{r['cve_id']}",
            )
        )
    return RankingsResponse(items=items)
