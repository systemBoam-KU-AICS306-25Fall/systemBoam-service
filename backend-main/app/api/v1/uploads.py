# app/api/v1/uploads.py
from __future__ import annotations

from typing import List

from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel, Field

# Router for upload-related APIs
router = APIRouter(prefix="/api/v1/uploads", tags=["uploads"])


class ScanResult(BaseModel):
    """One CVE match entry from a scan feed."""
    cve: str
    product: str


class ScanFeedResponse(BaseModel):
    """Response model for scan-feed uploads."""
    results: List[ScanResult] = Field(default_factory=list)


@router.post("/scan-feed", response_model=ScanFeedResponse)
async def upload_scan_feed(file: UploadFile = File(...)):
    """
    Accept a scan feed file and return matched CVEs/products.
    """
    # Consume the uploaded file to avoid unused file warnings.
    content = await file.read()
    _ = content

    # TODO: parse `content` and fill `results` with real data.
    return ScanFeedResponse(results=[])
