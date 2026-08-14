from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class Endpoint:
    path: str
    method: Literal["GET", "POST"]


ENDPOINTS = {
    "upload": Endpoint("/api/v1/upload", "POST"),
    "scan": Endpoint("/api/v1/scan", "POST"),
    "scan_logs": Endpoint("/api/v1/scan_logs", "POST"),
    "search": Endpoint("/api/v1/search", "POST"),
    "scans": Endpoint("/api/v1/scans", "GET"),
    "tasks": Endpoint("/api/v1/tasks", "POST"),
    "scorecard": Endpoint("/api/v1/scorecard", "POST"),
    "download_pdf": Endpoint("/api/v1/download_pdf", "POST"),
    "report_json": Endpoint("/api/v1/report_json", "POST"),
    "view_source": Endpoint("/api/v1/view_source", "POST"),
    "compare": Endpoint("/api/v1/compare", "POST"),
    "dynamic_get_apps": Endpoint("/api/v1/dynamic/get_apps", "POST"),
    "dynamic_start_analysis": Endpoint("/api/v1/dynamic/start_analysis", "POST"),
    "dynamic_report_json": Endpoint("/api/v1/dynamic/report_json", "POST"),
    "dynamic_stop_analysis": Endpoint("/api/v1/dynamic/stop_analysis", "POST"),
}
