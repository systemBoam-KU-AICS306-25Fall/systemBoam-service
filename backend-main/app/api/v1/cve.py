# app/api/v1/cve.py
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field
from sqlalchemy import text

# DB engine
try:
    from app.db import engine
except Exception:
    engine = None

# Router for CVE-related APIs
router = APIRouter(prefix="/api/v1/cve", tags=["cve"])


def ensure_engine():
    """Ensure SQLAlchemy engine is initialized before handling queries."""
    if engine is None:
        raise HTTPException(status_code=500, detail="DB engine is not initialized.")


# ---------- 2.1 Basic information ----------

class BasicResp(BaseModel):
    """Basic CVE information response model."""
    cve: str
    summary: Optional[str] = None


@router.get("/{cve}/basic", response_model=BasicResp)
def get_basic(cve: str):
    """Return basic CVE information (ID and summary) from core.cves."""
    ensure_engine()
    sql = text("""
        SELECT cve_id, summary
        FROM core.cves
        WHERE cve_id = :cve
    """)
    with engine.begin() as conn:
        row = conn.execute(sql, {"cve": cve}).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="CVE not found")
        return BasicResp(cve=row["cve_id"], summary=row["summary"])


# ---------- 2.2 Scores and overall summary ----------

class ScoresResp(BaseModel):
    """
    Score summary response for a CVE.

    Fields:
        - cve: CVE ID
        - overall_score: weighted combined score
        - cvss: dict containing base CVSS score (e.g. {"base": 9.8})
        - epss: EPSS score (0..1)
        - kve: KVE score (0..10)
        - activity: activity score (0..10)
    """
    cve: str
    overall_score: float
    cvss: dict = Field(default_factory=dict)        # e.g., { "base": 9.8 }
    epss: Optional[float] = None                    # 0..1
    kve: Optional[float] = None                     # 0..10
    activity: Optional[float] = None                # 0..10


@router.get("/{cve}/scores", response_model=ScoresResp)
def get_scores(cve: str, window: str = "7d"):
    """
    Return score summary using existing columns only.

    Sources (all columns already exist in your schema):
      - core.cves.cvss_score (0..10)
      - EPSS from core.epss.epss (fallback to cves.epss_score; 0..1)
      - KVE from core.kve.kve_score (optional; 0..10)
      - Activity from core.activity.activity_score (optional; 0..10, filtered by window)

    Weighted overall score:
        overall =
          0.60 * cvss +
          0.25 * (epss * 10.0) +
          0.10 * kve +
          0.05 * activity
    """
    ensure_engine()

    # Join existing score signals from core tables
    sql = text("""
        SELECT
          c.cve_id,
          c.cvss_score                                        AS cvss,
          COALESCE(e.epss, c.epss_score)                      AS epss,
          k.kve_score                                         AS kve,
          a.activity_score                                    AS activity
        FROM core.cves c
        LEFT JOIN core.epss     e ON e.cve_id = c.cve_id
        LEFT JOIN core.kve      k ON k.cve_id = c.cve_id
        LEFT JOIN core.activity a ON a.cve_id = c.cve_id AND a.time_window = :window
        WHERE c.cve_id = :cve
        LIMIT 1
    """)

    # Use a regular connection (no explicit transaction needed for read-only SELECT)
    with engine.connect() as conn:
        row = conn.execute(sql, {"cve": cve, "window": window}).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="CVE not found")

    # Safely convert nullable columns to floats, defaulting to 0.0
    cvss = float(row.get("cvss") or 0.0)       # 0..10
    epss = float(row.get("epss") or 0.0)       # 0..1
    kve  = float(row.get("kve") or 0.0)        # 0..10
    act  = float(row.get("activity") or 0.0)   # 0..10

    # Simple weighted overall score (scale is roughly 0..10)
    overall = 0.60 * cvss + 0.25 * (epss * 10.0) + 0.10 * kve + 0.05 * act

    return ScoresResp(
        cve=cve,
        overall_score=round(overall, 2),
        cvss={"base": round(cvss, 2)},
        epss=round(epss, 4),
        kve=round(kve, 2),
        activity=round(act, 2),
    )


# ---------- 2.3 Stats ----------

class StatsResp(BaseModel):
    """
    Placeholder statistics for a CVE.

    Note:
        - views/use_cases/interest are not stored in current schema and are fixed to 0.
    """
    cve: str
    views: int
    use_cases: int
    interest: float              # 0..1
    published_at: Optional[str]  # ISO8601


@router.get("/{cve}/stats", response_model=StatsResp)
def get_stats(cve: str):
    """
    Return basic placeholder stats for a CVE.

    Behavior:
        - If the CVE does not exist in core.cves, return 404.
        - If it exists, always return:
            views      = 0
            use_cases  = 0
            interest   = 0.0
            published_at = None (not loaded from DB yet)
    """
    ensure_engine()

    # Reuse get_basic() just to check that the CVE exists.
    _ = get_basic(cve)

    # Return static placeholder stats
    return StatsResp(
        cve=cve,
        views=0,
        use_cases=0,
        interest=0.0,
        published_at=None,
    )


# ---------- 2.4 AI summary ----------

class AISummaryResp(BaseModel):
    """Simple AI-style summary response."""
    ai_summary: str


@router.post("/{cve}/ai-summary", response_model=AISummaryResp)
def post_ai_summary(cve: str, window: str = "7d"):
    """
    Build a template-based summary for a CVE.

    This does not call any external LLM; it only uses the CVE's scores and basic info.
    """
    ensure_engine()

    scores = get_scores(cve, window=window)
    basic  = get_basic(cve)

    cvss = float(scores.cvss.get("base") or 0.0)
    epss = float(scores.epss or 0.0)
    kve  = float(scores.kve or 0.0)
    act  = float(scores.activity or 0.0)
    overall = float(scores.overall_score or 0.0)
    summary = (basic.summary or "").strip()

    # CVSS 기반 심각도 구간
    if cvss >= 9.0:
        severity_label = "극히 높은 심각도"
    elif cvss >= 7.0:
        severity_label = "높은 심각도"
    elif cvss >= 4.0:
        severity_label = "중간 수준의 심각도"
    else:
        severity_label = "낮은 심각도"

    # EPSS 기반 악용 가능성
    if epss >= 0.7:
        exploit_label = "실제 악용 가능성이 매우 높은 편입니다."
    elif epss >= 0.4:
        exploit_label = "실제 악용 가능성이 중간 이상입니다."
    elif epss > 0.0:
        exploit_label = "실제 악용 가능성은 상대적으로 낮은 편입니다."
    else:
        exploit_label = "EPSS 데이터가 없어 악용 가능성을 추정하기 어렵습니다."

    # KVE 기반 노출도
    if kve >= 8.0:
        exposure_label = "내부 자산 관점에서 노출도가 매우 높아 우선 대응이 필요합니다."
    elif kve >= 5.0:
        exposure_label = "내부 자산 관점에서 노출도가 중간 수준으로 관리가 필요합니다."
    elif kve > 0.0:
        exposure_label = "내부 자산 관점에서 노출도가 낮은 편입니다."
    else:
        exposure_label = "KVE 데이터가 없어 자산 노출도는 기본값(0)으로 간주합니다."

    # 활동도 기반 문구
    if act >= 7.0:
        activity_label = "최근 관측된 공격 활동이 활발한 편입니다."
    elif act >= 3.0:
        activity_label = "최근 일부 공격 활동이 관측되었습니다."
    elif act > 0.0:
        activity_label = "최근 공격 활동은 거의 없지만 잠재적 리스크는 존재합니다."
    else:
        activity_label = "관련 공격 활동 데이터가 없거나 거의 관측되지 않았습니다."

    parts = []

    head = f"{basic.cve}는 {severity_label}의 취약점입니다."
    if summary:
        head += f" 요약 설명: {summary}"
    parts.append(head)

    parts.append(
        f"CVSS 점수는 {cvss:.1f}, EPSS {epss:.2f}, KVE {kve:.1f}, 활동도 {act:.1f}이며 "
        f"이를 바탕으로 한 종합 점수는 {overall:.2f}입니다."
    )

    parts.append(f"{exploit_label} {exposure_label} {activity_label}")

    msg = " ".join(parts)
    return AISummaryResp(ai_summary=msg)


# ---------- 2.5 Related CVEs ----------

class RelatedItem(BaseModel):
    """One related CVE item with risk level."""
    cve: str
    risk_level: str
    score: float


class RelatedResp(BaseModel):
    """List of related CVE items."""
    related: List[RelatedItem] = Field(default_factory=list)


@router.get("/{cve}/related", response_model=RelatedResp)
def get_related(cve: str, limit: int = 5):
    """
    Return heuristic related CVEs.

    There is no dedicated similarity table yet.
    Heuristic:
      - If the year can be parsed from the CVE ID, pick top-scoring CVEs from the same year.
      - Otherwise, use global ranking by the computed score.

    Note: This still uses legacy columns (cvss_v31_score, etc.) and may need schema alignment.
    """
    ensure_engine()
    year_prefix = cve.split("-")[1] if "-" in cve else None
    if not year_prefix or not year_prefix.isdigit():
        year_filter = ""
        params = {"cve": cve, "limit": limit}
    else:
        year_filter = "AND c.cve_id LIKE :year_like"
        params = {"cve": cve, "year_like": f"CVE-{year_prefix}-%", "limit": limit}

    sql = text(f"""
        WITH base AS (
            SELECT
              c.cve_id,
              COALESCE(c.cvss_v31_score, 0)::float AS cvss,
              COALESCE(e.epss, 0)::float           AS epss,
              COALESCE(k.kve_score,
                       CASE WHEN kv.kev_flag THEN 10.0 ELSE 0.0 END, 0)::float AS kve,
              COALESCE(a.activity_score, 0)::float AS activity
            FROM core.cves c
            LEFT JOIN core.epss     e  USING (cve_id)
            LEFT JOIN core.kve      k  USING (cve_id)
            LEFT JOIN core.kev      kv USING (cve_id)
            LEFT JOIN core.activity a  ON a.cve_id = c.cve_id AND a.time_window = '7d'
            WHERE c.cve_id <> :cve
            {year_filter}
        )
        SELECT
          cve_id,
          100.0*(0.30*(cvss/10.0)+0.40*(epss)+0.20*(kve/10.0)+0.10*(activity/10.0)) AS score
        FROM base
        ORDER BY score DESC NULLS LAST, cve_id ASC
        LIMIT :limit
    """)
    with engine.begin() as conn:
        rows = conn.execute(sql, params).mappings().all()

    items: List[RelatedItem] = []
    for r in rows:
        s = float(r["score"])
        level = "high" if s >= 85 else "medium" if s >= 60 else "low"
        items.append(RelatedItem(cve=r["cve_id"], risk_level=level, score=round(s, 1)))
    return RelatedResp(related=items)


# ---------- 2.6 Timeline ----------

class TimelineItem(BaseModel):
    """One timeline event for a CVE."""
    name: str
    date: str


class TimelineResp(BaseModel):
    """Timeline response containing events for a CVE."""
    timeline: List[TimelineItem]


@router.get("/{cve}/timeline", response_model=TimelineResp)
def get_timeline(cve: str):
    """
    Return a simple timeline for a CVE using:

      - core.cves.published
      - core.cves.last_modified
    """
    ensure_engine()
    sql = text("""
        SELECT published, last_modified
        FROM core.cves
        WHERE cve_id = :cve
    """)
    with engine.begin() as conn:
        r = conn.execute(sql, {"cve": cve}).mappings().first()
        if not r:
            raise HTTPException(status_code=404, detail="CVE not found")

    items: List[TimelineItem] = []
    if r["published"]:
        items.append(TimelineItem(name="Published", date=r["published"].isoformat()))
    if r["last_modified"]:
        items.append(TimelineItem(name="Last Modified", date=r["last_modified"].isoformat()))
    return TimelineResp(timeline=items)


# ---------- 2.7 Evidence search ----------

class EvidenceSearchReq(BaseModel):
    """Request payload for evidence search."""
    query: str


class EvidenceHit(BaseModel):
    """One evidence search hit (e.g., blog, PoC repo, etc.)."""
    title: str
    product: Optional[str] = None
    type: str
    link: str


class EvidenceSearchResp(BaseModel):
    """Evidence search response containing a list of hits."""
    hits: List[EvidenceHit] = Field(default_factory=list)


@router.post("/{cve}/evidence/search", response_model=EvidenceSearchResp)
def post_evidence_search(cve: str, payload: EvidenceSearchReq = Body(...)):
    """
    Placeholder for evidence search.

    Currently:
      - No search index in the current schema.
      - Always returns an empty result list.

    Intended future data sources:
      - GitHub PoCs
      - Exploit DB
      - Security blogs, etc.
    """
    _ = cve
    _ = payload.query
    return EvidenceSearchResp(hits=[])


# ---------- 2.8 PoC / patches / advisories ----------

class AdvisoryItem(BaseModel):
    """One advisory-related item (PoC / patch / advisory)."""
    type: str   # poc | patch | advisory
    link: str


class AdvisoriesResp(BaseModel):
    """Advisories response list."""
    items: List[AdvisoryItem] = Field(default_factory=list)


@router.get("/{cve}/advisories", response_model=AdvisoriesResp)
def get_advisories(cve: str):
    """
    Placeholder for advisories.

    Currently:
      - No advisories table exists.
      - Always returns an empty list.

    Intended future source:
      - core.advisories (or equivalent).
    """
    _ = cve
    return AdvisoriesResp(items=[])


# ---------- 2.9 AI recommendations ----------

class Recommendation(BaseModel):
    """One AI-style recommendation entry."""
    type: str
    action: str


class AIRecsResp(BaseModel):
    """AI recommendations response model for a given CVE."""
    cve: str
    recommendations: List[Recommendation]


@router.post("/{cve}/ai-recommendations", response_model=AIRecsResp)
def post_ai_recommendations(cve: str, window: str = "7d"):
    """
    Simple rule-based recommendations based on scores:

      - If CVSS >= 9.0 or overall >= 90 → urgent patch
      - If EPSS >= 0.5              → monitoring / blocking rules
      - If KVE  >= 8.0              → additional mitigations

    Note:
      - The current overall_score scale is around 0..10 due to the
        linear combination used in get_scores. The threshold 'overall >= 90'
        is effectively unreachable with this scale and should be adjusted
        if you want to use overall_score as a trigger.
    """
    scores = get_scores(cve, window=window)
    recs: List[Recommendation] = []

    overall = scores.overall_score
    cvss = float(scores.cvss.get("base") or 0)
    epss = float(scores.epss or 0)
    kve = float(scores.kve or 0)

    # Urgent patch condition (note: overall >= 90 is not realistic with current scale)
    if cvss >= 9.0 or overall >= 90.0:
        recs.append(
            Recommendation(
                type="urgent_patch",
                action="Apply vendor patch immediately (if available).",
            )
        )
    # Monitoring and blocking recommendation based on EPSS
    if epss >= 0.5:
        recs.append(
            Recommendation(
                type="monitoring",
                action="Deploy IDS/WAF signatures and block known IoCs/PoCs.",
            )
        )
    # Additional mitigation recommendation based on KVE
    if kve >= 8.0:
        recs.append(
            Recommendation(
                type="mitigation",
                action="Disable vulnerable features and restrict exposure surface.",
            )
        )

    # Default recommendation when no strong signals are present
    if not recs:
        recs.append(
            Recommendation(
                type="review",
                action="Track vendor advisories and schedule regular updates.",
            )
        )

    return AIRecsResp(cve=cve, recommendations=recs)
