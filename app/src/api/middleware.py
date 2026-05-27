from __future__ import annotations

import csv
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Propagate a request ID across the pipeline.
    - Reuses X-Request-Id if already present in the incoming request.
    - Generates a new UUID otherwise.
    - Stores it in request.state.request_id and echoes it in the response header.
    """
    def __init__(self, app, header_name: str = "X-Request-Id"):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.header_name) or str(uuid.uuid4())
        request.state.request_id = rid

        response: Response = await call_next(request)
        response.headers[self.header_name] = rid
        return response


class LatencyCSVLogger(BaseHTTPMiddleware):
    """
    Measure request latency and append one row per request to a CSV file.
    Prompt content is never logged; only byte lengths are recorded.

    Columns: ts_utc, scenario, method, path, status_code, latency_ms,
             request_id, garak_tag, prompt_len, response_len
    """
    def __init__(
        self,
        app,
        scenario: str,
        domain: str,
        csv_path: str,
        tag_header: str = "X-Garak-Tag",
        include_lengths: bool = True,
        only_if_header: Optional[tuple[str, str]] = None,
        skip_if_header: Optional[tuple[str, str]] = None,
    ):
        super().__init__(app)
        self.scenario = scenario
        self.domain = domain
        self.csv_path = Path(csv_path)
        self.tag_header = tag_header
        self.include_lengths = include_lengths
        self.only_if_header = only_if_header
        self.skip_if_header = skip_if_header

        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_header()

    def _ensure_header(self) -> None:
        if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
            return
        header = [
            "ts_utc",
            "scenario",
            "domain",
            "method",
            "path",
            "status_code",
            "latency_ms",
            "request_id",
            "garak_tag",
        ]
        if self.include_lengths:
            header += ["prompt_len", "response_len"]
        header += ["run_id"]

        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    @staticmethod
    def _safe_len(value: Optional[str]) -> int:
        return len(value) if value else 0

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()

        # Route requests to the appropriate scenario bucket based on header filters.
        if self.only_if_header is not None:
            hk, hv = self.only_if_header
            if request.headers.get(hk, "") != hv:
                return await call_next(request)

        if self.skip_if_header is not None:
            hk, hv = self.skip_if_header
            if request.headers.get(hk, "") == hv:
                return await call_next(request)

        # Prefer the request ID set by RequestIdMiddleware; fall back to the raw header.
        request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-Id", "")

        # Probe tag set by Garak's RestGenerator; used to correlate latency with specific probes.
        garak_tag = request.headers.get(self.tag_header, "")

        prompt_len = 0
        if self.include_lengths:
            try:
                body = await request.body()
                # Reading the body consumes the stream, but Starlette caches it so downstream handlers are unaffected.
                prompt_len = len(body)
            except Exception:
                prompt_len = 0

        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            response_len = 0
            if self.include_lengths:
                response_len = getattr(request.state, "response_len", 0)


            run_id = os.getenv("RUN_ID", "")

            row = [
                self._utc_now_iso(),
                self.scenario,
                self.domain,
                request.method,
                request.url.path,
                status_code if "status_code" in locals() else 500,
                round(elapsed_ms, 3),
                request_id,
                garak_tag,
            ]
            if self.include_lengths:
                row += [prompt_len, response_len]
            row += [run_id]

            with self.csv_path.open("a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(row)
