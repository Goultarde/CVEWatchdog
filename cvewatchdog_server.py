import argparse
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from CVEWatchdog import get_cvss_severity, resolve_software, run_sploitscan, write_html_report


JOBS = {}
JOBS_LOCK = threading.Lock()
EXECUTOR = ThreadPoolExecutor(max_workers=1)
LOGGER = logging.getLogger("uvicorn.error")


def validate_inventory(payload):
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")
    platform_name = payload.get("platform")
    if platform_name not in ("windows", "linux", "macos"):
        raise ValueError("platform must be windows, linux, or macos")
    software = payload.get("software")
    if not isinstance(software, list) or not software:
        raise ValueError("software must be a non-empty list")
    if len(software) > 10000:
        raise ValueError("software inventory is limited to 10000 entries")
    normalized = []
    for item in software:
        if not isinstance(item, dict):
            raise ValueError("each software entry must be an object")
        name = item.get("name")
        version = item.get("version")
        context = item.get("context", "")
        if not isinstance(name, str) or not name.strip() or len(name) > 500:
            raise ValueError("software name is required and limited to 500 characters")
        if not isinstance(version, str) or not version.strip() or len(version) > 200:
            raise ValueError("software version is required and limited to 200 characters")
        if not isinstance(context, str) or len(context) > 4000:
            raise ValueError("software context is limited to 4000 characters")
        normalized.append({"name": name.strip(), "version": version.strip(), "context": context})
    options = payload.get("options") or {}
    if not isinstance(options, dict) or not isinstance(options.get("sploitscan", True), bool):
        raise ValueError("options.sploitscan must be a boolean")
    return {
        "hostname": str(payload.get("hostname") or "unknown")[:255],
        "platform": platform_name,
        "software": normalized,
        "sploitscan": options.get("sploitscan", True),
    }


def make_summary(software_count, resolved_count, api_errors, cves):
    counts = {
        name.lower(): sum(1 for cve in cves if get_cvss_severity(cve.get("cvss_score")) == name)
        for name in ("Critical", "High", "Medium", "Low")
    }
    risk = "🟢 LOW RISK"
    if counts["critical"]:
        risk = "⚫️ CRITICAL RISK"
    elif counts["high"] > 3:
        risk = "🔴 HIGH RISK"
    elif counts["high"]:
        risk = "🟠 MEDIUM RISK"
    return {
        "software_scanned": software_count,
        "software_resolved": resolved_count,
        "api_errors": api_errors,
        "total_cves": len(cves),
        **counts,
        "risk_level": risk,
    }


def build_report(job_id, inventory, fastcve_url, reports_dir):
    try:
        with JOBS_LOCK:
            JOBS[job_id].update(status="running", stage="FastCVE resolution")
        vulnerable = []
        all_cves = []
        resolved = 0
        api_errors = 0
        for index, item in enumerate(inventory["software"], 1):
            try:
                result = resolve_software(
                    fastcve_url, item["name"], item["version"], item["context"], inventory["platform"]
                )
            except (requests.RequestException, ValueError):
                api_errors += 1
                result = {}
            matched_cpe = result.get("matched_cpe")
            cves = result.get("results") or []
            if matched_cpe:
                resolved += 1
            if matched_cpe and cves:
                vulnerable.append({
                    "name": item["name"],
                    "version": item["version"],
                    "cpe": matched_cpe["cpe"],
                    "cves": cves,
                })
                all_cves.extend(cves)
            with JOBS_LOCK:
                JOBS[job_id]["processed"] = index

        if api_errors == len(inventory["software"]):
            raise RuntimeError("FastCVE-API failed for every software entry")

        intelligence = None
        if inventory["sploitscan"] and all_cves:
            cve_count = len(set(cve.get("cve_id") for cve in all_cves if cve.get("cve_id")))
            with JOBS_LOCK:
                JOBS[job_id].update(stage="SploitScan enrichment", processed=0, total=cve_count)
            LOGGER.info("SploitScan enrichment started for %d CVEs (report %s)", cve_count, job_id)
            intelligence = run_sploitscan(all_cves)
            LOGGER.info("SploitScan enrichment completed for %d CVEs (report %s)", cve_count, job_id)

        summary = make_summary(len(inventory["software"]), resolved, api_errors, all_cves)
        report_path = reports_dir / f"{job_id}.html"
        write_html_report(report_path, vulnerable, summary, intelligence)
        with JOBS_LOCK:
            JOBS[job_id].update(
                status="completed",
                stage="completed",
                processed=JOBS[job_id]["total"],
                summary=summary,
                report_path=str(report_path),
            )
    except Exception as error:
        with JOBS_LOCK:
            JOBS[job_id].update(status="failed", stage="failed", error=str(error))


def create_app(fastcve_url="http://localhost:8001", reports_dir=None):
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import FileResponse
    except ImportError as error:
        raise RuntimeError("Server dependencies are missing; reinstall CVEWatchdog with pipx --force") from error

    report_root = Path(reports_dir or "~/.local/share/cvewatchdog/reports").expanduser().resolve()
    report_root.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="CVEWatchdog Server", version="2.0.1")

    @app.get("/health")
    def health():
        try:
            response = requests.get(f"{fastcve_url.rstrip('/')}/health", timeout=5)
            response.raise_for_status()
            fastcve = response.json()
            return {"status": "ok", "fastcve": "connected", "cves_indexed": fastcve.get("cves_indexed", 0)}
        except (requests.RequestException, ValueError):
            return {"status": "degraded", "fastcve": "unavailable", "cves_indexed": 0}

    @app.post("/api/v1/reports", status_code=202)
    async def create_report(request: Request):
        try:
            inventory = validate_inventory(await request.json())
        except (ValueError, TypeError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            JOBS[job_id] = {
                "id": job_id,
                "status": "queued",
                "stage": "queued",
                "processed": 0,
                "total": len(inventory["software"]),
                "hostname": inventory["hostname"],
            }
        EXECUTOR.submit(build_report, job_id, inventory, fastcve_url, report_root)
        return {"id": job_id, "status": "queued", "status_url": f"/api/v1/reports/{job_id}"}

    @app.get("/api/v1/reports/{job_id}")
    def report_status(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Report not found")
            return {key: value for key, value in job.items() if key != "report_path"}

    @app.get("/api/v1/reports/{job_id}/html")
    def report_html(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Report not found")
            if job["status"] != "completed":
                raise HTTPException(status_code=409, detail="Report is not ready")
            path = job["report_path"]
        return FileResponse(path, media_type="text/html", filename=f"cvewatchdog-{job_id}.html")

    return app


def main():
    parser = argparse.ArgumentParser(description="CVEWatchdog report server")
    parser.add_argument("--fastcve-url", default="http://localhost:8001")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--reports-dir", default="~/.local/share/cvewatchdog/reports")
    args = parser.parse_args()
    try:
        import uvicorn
    except ImportError as error:
        raise SystemExit("Server dependencies are missing; reinstall CVEWatchdog with pipx --force") from error
    uvicorn.run(create_app(args.fastcve_url, args.reports_dir), host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
