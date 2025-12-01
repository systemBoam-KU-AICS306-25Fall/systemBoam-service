import json
import sys
from pathlib import Path
from decimal import Decimal, InvalidOperation

# 프로젝트 루트(backend-main)를 sys.path에 추가 (app 패키지 import 위해)
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from sqlalchemy import text
from app.db import engine


# JSON 디렉터리: ~/data/run_20251125_094959
DATA_DIR = (Path.home() / "data" / "run_20251125_094959").resolve()


def extract_description(data: dict) -> str:
    """
    JSON 안에서 설명/요약 텍스트를 뽑아옵니다.
    JSON 구조는 모르기 때문에 대표적인 키 이름만 우선 시도합니다. (추측입니다)
    필요하면 candidate_keys를 실제 구조에 맞게 바꾸세요.
    """
    candidate_keys = ["description", "summary", "details"]

    for key in candidate_keys:
        if key not in data:
            continue
        val = data[key]

        if isinstance(val, dict):
            for subkey in ["en", "ko", "value", "text"]:
                if subkey in val and isinstance(val[subkey], str):
                    return val[subkey]
            for v in val.values():
                if isinstance(v, str):
                    return v
        elif isinstance(val, str):
            return val

    return ""


def _get_nested(d: dict, path: tuple[str, ...]):
    """
    path = ('metrics', 'cvss', 'baseScore') 형태로 들어오면
    d['metrics']['cvss']['baseScore'] 를 시도해서 가져옵니다.
    """
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        if k not in cur:
            return None
        cur = cur[k]
    return cur


def _to_decimal(v):
    if v is None:
        return None
    try:
        if isinstance(v, (int, float, str)):
            return Decimal(str(v))
    except (InvalidOperation, ValueError):
        return None
    return None


def extract_scores(data: dict) -> dict:
    """
    이 JSON 구조를 기준으로 점수를 추출합니다.

    - cvss_score  : ows_score.score (0~10 스케일)
    - epss_score  : ows_score.components.exploitation (0~1 근사)
    - severity    : cvss_score를 기준으로 HIGH/MEDIUM/LOW 등 산출 (임의 규칙, 추측입니다)
    """
    cvss_score = None
    epss_score = None
    severity = None

    ows = data.get("ows_score") or {}
    if isinstance(ows, dict):
        cvss_score = _to_decimal(ows.get("score"))

        comps = ows.get("components") or {}
        if isinstance(comps, dict):
            epss_score = _to_decimal(comps.get("exploitation"))

    # severity는 cvss_score 구간으로 단순 매핑 (임의 규칙, 추측입니다)
    if cvss_score is not None:
        if cvss_score >= Decimal("9.0"):
            severity = "CRITICAL"
        elif cvss_score >= Decimal("7.0"):
            severity = "HIGH"
        elif cvss_score >= Decimal("4.0"):
            severity = "MEDIUM"
        elif cvss_score > Decimal("0"):
            severity = "LOW"
        else:
            severity = "NONE"

    return {
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "severity": severity,
    }


def detect_columns():
    """
    core.cves 테이블에서 실제 컬럼 목록을 읽어와,
    - 설명/요약으로 쓸 컬럼 이름(desc_col)
    - raw_json 컬럼 존재 여부(has_raw_json)
    - raw 컬럼의 NOT NULL 여부 및 타입(raw_nullable, raw_type)
    - cvss_score / epss_score / severity 컬럼 존재 여부
    를 자동으로 판별합니다.
    """
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT column_name, is_nullable, data_type
                FROM information_schema.columns
                WHERE table_schema = 'core'
                  AND table_name   = 'cves'
                """
            )
        ).fetchall()

    cols = [r[0] for r in rows]
    print("core.cves 컬럼 목록:", cols)

    # 설명/요약 컬럼 후보 (우선순위)
    desc_candidates = [
        "summary",
        "description",
        "title",
        "short_description",
        "details",
    ]

    desc_col = None
    for c in desc_candidates:
        if c in cols:
            desc_col = c
            break

    if desc_col is None:
        raise SystemExit(
            "설명용으로 사용할 컬럼을 찾지 못했습니다. "
            "core.cves에 summary/description/title 등 어떤 컬럼이 있는지 보고, "
            "desc_candidates 리스트를 수정해 주세요."
        )

    has_raw_json = "raw_json" in cols

    raw_nullable = None
    raw_type = None
    if "raw" in cols:
        for col_name, is_nullable, data_type in rows:
            if col_name == "raw":
                raw_nullable = is_nullable  # 'YES' 또는 'NO'
                raw_type = data_type
                break

    has_cvss = "cvss_score" in cols
    has_epss = "epss_score" in cols
    has_severity = "severity" in cols

    print(f"선택된 설명 컬럼: {desc_col}")
    print(f"raw_json 컬럼 존재 여부: {has_raw_json}")
    if raw_type is not None:
        print(f"raw 컬럼 타입: {raw_type}, NULL 허용 여부: {raw_nullable}")
    else:
        print("raw 컬럼이 없습니다.")
    print(f"cvss_score 컬럼 존재 여부: {has_cvss}")
    print(f"epss_score 컬럼 존재 여부: {has_epss}")
    print(f"severity 컬럼 존재 여부: {has_severity}")

    return desc_col, has_raw_json, raw_nullable, raw_type, has_cvss, has_epss, has_severity


def build_raw_value(raw_type: str | None, raw_json_str: str):
    """
    raw 컬럼에 들어갈 값을 생성합니다.
    - raw가 json/jsonb/text/varchar인 경우: raw_json_str 그대로 사용
    - 그 외 타입이면 자동 처리 불가 → 종료
    """
    if raw_type is None:
        return None

    t = raw_type.lower()
    if t in ("json", "jsonb", "text", "character varying"):
        return raw_json_str

    raise SystemExit(
        f"raw 컬럼 타입 {raw_type} 은(는) 자동으로 처리하기 어렵습니다. "
        "스크립트에서 build_raw_value 함수를 수정해 주세요."
    )


def main():
    if not DATA_DIR.exists():
        raise SystemExit(f"데이터 디렉터리를 찾을 수 없습니다: {DATA_DIR}")

    json_files = sorted(DATA_DIR.glob("CVE-*.json"))
    if not json_files:
        raise SystemExit(f"JSON 파일을 찾을 수 없습니다: {DATA_DIR}")

    print(f"{len(json_files)}개의 CVE JSON 파일을 찾았습니다.")
    print("DB URL:", engine.url)

    (
        desc_col,
        has_raw_json,
        raw_nullable,
        raw_type,
        has_cvss,
        has_epss,
        has_severity,
    ) = detect_columns()

    # raw가 NOT NULL이면 반드시 값을 넣어야 합니다.
    need_raw = (raw_type is not None and raw_nullable == "NO")

    # --- UPDATE SQL 동적 구성 ---
    set_clauses = [f"{desc_col} = COALESCE({desc_col}, :summary)"]
    if need_raw:
        set_clauses.append("raw = COALESCE(raw, :raw)")
    if has_raw_json:
        set_clauses.append("raw_json = :raw_json")
    if has_cvss:
        set_clauses.append("cvss_score = COALESCE(:cvss_score, cvss_score)")
    if has_epss:
        set_clauses.append("epss_score = COALESCE(:epss_score, epss_score)")
    if has_severity:
        set_clauses.append("severity = COALESCE(:severity, severity)")

    update_sql = text(
        f"""
        UPDATE core.cves
        SET {", ".join(set_clauses)}
        WHERE cve_id = :cve_id
        """
    )

    # --- INSERT SQL 동적 구성 ---
    insert_cols = ["cve_id", desc_col]
    insert_vals = [":cve_id", ":summary"]
    if need_raw:
        insert_cols.append("raw")
        insert_vals.append(":raw")
    if has_raw_json:
        insert_cols.append("raw_json")
        insert_vals.append(":raw_json")
    if has_cvss:
        insert_cols.append("cvss_score")
        insert_vals.append(":cvss_score")
    if has_epss:
        insert_cols.append("epss_score")
        insert_vals.append(":epss_score")
    if has_severity:
        insert_cols.append("severity")
        insert_vals.append(":severity")

    insert_sql = text(
        f"""
        INSERT INTO core.cves ({", ".join(insert_cols)})
        VALUES ({", ".join(insert_vals)})
        """
    )

    updated = 0
    inserted = 0

    with engine.begin() as conn:
        for path in json_files:
            cve_id = path.stem  # 예: "CVE-2012-1823"

            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            description = extract_description(data)
            raw_json_str = json.dumps(data, ensure_ascii=False)
            scores = extract_scores(data)

            params = {
                "cve_id": cve_id,
                "summary": description,
            }
            if has_raw_json:
                params["raw_json"] = raw_json_str
            if need_raw:
                params["raw"] = build_raw_value(raw_type, raw_json_str)
            if has_cvss:
                params["cvss_score"] = scores.get("cvss_score")
            if has_epss:
                params["epss_score"] = scores.get("epss_score")
            if has_severity:
                params["severity"] = scores.get("severity")

            # 1차: UPDATE 시도
            result = conn.execute(update_sql, params)

            if result.rowcount and result.rowcount > 0:
                print(f"[업데이트됨] {cve_id} (rowcount={result.rowcount})")
                updated += 1
                continue

            # 2차: 없다면 INSERT
            conn.execute(insert_sql, params)
            print(f"[삽입됨] {cve_id}")
            inserted += 1

    print(f"업데이트된 행 수: {updated}")
    print(f"새로 삽입된 CVE 수: {inserted}")
    print("모든 JSON 처리 완료.")


if __name__ == "__main__":
    main()
