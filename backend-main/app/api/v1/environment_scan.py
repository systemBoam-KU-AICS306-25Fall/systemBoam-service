# app/api/v1/environment_scan.py

import json
import shutil
import subprocess
import uuid
import datetime
import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, status

router = APIRouter(
    prefix="/api/v1/environment",
    tags=["environment"],
)


def _run_sbom_tool(
    input_zip_path: Path,
    work_dir: Path,
    package_name: str,
    package_version: str = "1.0.0",
) -> Path:
    """
    After unzipping the uploaded ZIP file, execute sbom-tool
    and return the generated manifest.spdx.json file path.
    """

    project_dir = work_dir / "project"
    manifest_root = work_dir / "sbom-out"

    project_dir.mkdir(parents=True, exist_ok=True)
    manifest_root.mkdir(parents=True, exist_ok=True)

    # 1) Unzip the uploaded project ZIP file.
    #    The server must have the 'unzip' utility installed.
    unzip_cmd = ["unzip", "-q", str(input_zip_path), "-d", str(project_dir)]
    try:
        subprocess.run(unzip_cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unzip uploaded file: {e}",
        )

    # 2) Run sbom-tool
    job_id = uuid.uuid4().hex
    namespace_base = f"https://systemboam.kro.kr/sbom/{job_id}"

    sbom_cmd = [
        "sbom-tool",
        "generate",
        "-b",
        str(project_dir),
        "-bc",
        str(project_dir),
        "-pn",
        package_name,
        "-pv",
        package_version,
        "-ps",
        "UserUpload",
        "-nsb",
        namespace_base,
        "-m",
        str(manifest_root),
        # For verbose logs if needed:
        # "-V", "Information",
    ]

    try:
        subprocess.run(sbom_cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"sbom-tool failed: {e}",
        )

    # 3) Locate manifest.spdx.json using glob search
    #    Default: {manifest_root}/_manifest/spdx_2.2/manifest.spdx.json
    manifest_path: Optional[Path] = None
    for p in manifest_root.rglob("manifest.spdx.json"):
        manifest_path = p
        break

    if manifest_path is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SBOM manifest.spdx.json not found after sbom-tool execution.",
        )

    return manifest_path


def _extract_basic_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract minimal component info from MS SBOM (spdx.json) required for CVE matching.
    Returns a simplified list of components containing:

    - name
    - versionInfo
    - externalRefs (purl, cpe23Type)
    """

    packages = sbom.get("packages", [])
    components: List[Dict[str, Any]] = []

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("versionInfo")
        spdx_id = pkg.get("SPDXID")

        purl = None
        cpe = None
        for ref in pkg.get("externalRefs", []):
            ref_type = ref.get("referenceType")
            locator = ref.get("referenceLocator")
            if ref_type == "purl":
                purl = locator
            elif ref_type == "cpe23Type":
                cpe = locator

        components.append(
            {
                "spdx_id": spdx_id,
                "name": name,
                "version": version,
                "purl": purl,
                "cpe23": cpe,
                "licenses": {
                    "declared": pkg.get("licenseDeclared"),
                    "concluded": pkg.get("licenseConcluded"),
                },
            }
        )

    return components


@router.post("/scan", summary="Environment scan: Analyze uploaded ZIP as SBOM")
async def scan_environment_from_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Process:
    - Receive the project ZIP file from frontend
    - Save it into ~/envScan/<timestamp_userid>/
    - Run sbom-tool
    - Read manifest.spdx.json and extract:
        * project metadata
        * component summary list

    CVE matching will be performed later by joining extracted components
    with the internal CVE database.
    """

    # Generate timestamp + user identification
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    user_id = getpass.getuser()  # or use JWT user ID in a real system
    unique_dir_name = f"{timestamp}_{user_id}_{uuid.uuid4().hex}"

    # Target storage: ~/envScan/<timestamp_userid_uuid>/
    base_dir = Path.home() / "envScan" / unique_dir_name
    base_dir.mkdir(parents=True, exist_ok=True)

    zip_path = base_dir / "input.zip"

    try:
        # Save uploaded ZIP file
        with zip_path.open("wb") as f:
            content = await file.read()
            f.write(content)

        # Run sbom-tool
        manifest_path = _run_sbom_tool(
            input_zip_path=zip_path,
            work_dir=base_dir,
            package_name=file.filename or "user-upload",
        )

        # Read SBOM manifest
        with manifest_path.open("r", encoding="utf-8") as f:
            sbom = json.load(f)

        # Build response summary
        components = _extract_basic_components(sbom)
        response: Dict[str, Any] = {
            "project": {
                "name": sbom.get("name"),
                "spdx_id": sbom.get("SPDXID"),
                "document_namespace": sbom.get("documentNamespace"),
            },
            "storage_path": str(base_dir),
            "summary": {
                "component_count": len(components),
            },
            "components": components,
        }

        return response

    except Exception:
        raise
