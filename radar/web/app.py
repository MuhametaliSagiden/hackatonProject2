import json
from contextlib import asynccontextmanager

from datetime import datetime

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from ..audit import audit
from ..db import session
from ..export.csv_export import export_csv
from ..export.html_export import export_html
from ..export.xlsx_export import export_xlsx
from ..models import AuditLog, CertResult, Service, NotificationLog, Scan, Setting
from ..services import (
    apply_settings,
    current_settings,
    dashboard_data,
    import_targets,
    latest_results,
    run_scan_background,
    scan_summary,
    service_history,
)
from ..notify.service import send_test
from ..scheduler import start_scheduler, update_scheduler
from ..config import ROOT, load_config

_scheduler = None


@asynccontextmanager
async def lifespan(app):
    global _scheduler
    if _scheduler is None:
        db = session()
        saved = db.get(Setting, "schedule_hours")
        db.close()
        hours = int(saved.value) if saved else load_config().get("scan", {}).get("schedule_hours", 0)
        _scheduler = start_scheduler(hours)
    yield
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None


app = FastAPI(title="Certificate Radar", lifespan=lifespan)
WEB_ROOT = ROOT / "radar" / "web"
templates = Jinja2Templates(directory=str(WEB_ROOT / "templates"))
templates.env.filters["ru_date"] = lambda value: (
    value.strftime("%d.%m.%Y")
    if isinstance(value, datetime)
    else "—"
    if value is None
    else str(value)
)
templates.env.filters["ru_datetime"] = lambda value: (
    value.strftime("%d.%m.%Y %H:%M")
    if isinstance(value, datetime)
    else "—"
    if value is None
    else str(value)
)
app.mount("/static", StaticFiles(directory=str(WEB_ROOT / "static")), name="static")


@app.get("/health")
def health():
    return {"status": "ok"}


def rows(filters: dict | None = None, sort: str = "days_left", direction: str = "asc"):
    return latest_results(filters=filters, sort=sort, direction=direction)


def result_filters(
    status: str | None = None,
    q: str | None = None,
    owner: str | None = None,
    issuer: str | None = None,
    risk_level: str | None = None,
    days_max: str | None = None,
) -> dict:
    return {
        "status": status or None,
        "q": q or None,
        "owner": owner or None,
        "issuer": issuer or None,
        "risk_level": risk_level or None,
        "days_max": days_max or None,
    }


def json_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    return []


@app.post("/api/import")
async def api_import(file: UploadFile = File(...)):
    report = import_targets(await file.read(), file.filename or "targets.txt")
    return {
        "added": report.added,
        "updated": report.updated,
        "duplicates": report.duplicates,
        "invalid": report.invalid,
    }


@app.get("/targets", response_class=HTMLResponse)
def targets_page(request: Request):
    db = session()
    items = list(db.exec(select(Service).order_by(Service.host)))
    db.close()
    return templates.TemplateResponse(request, "targets.html", {"items": items})


@app.post("/targets/import", response_class=HTMLResponse)
def targets_import(request: Request, target_text: str = Form(...)):
    report = import_targets(target_text.encode("utf-8"), "targets.txt")
    return templates.TemplateResponse(request, "import_result.html", {"report": report})


@app.post("/targets/upload", response_class=HTMLResponse)
async def targets_upload(request: Request, file: UploadFile = File(...)):
    report = import_targets(await file.read(), file.filename or "targets.txt")
    return templates.TemplateResponse(request, "import_result.html", {"report": report})


@app.post("/targets/{service_id}")
def update_target(service_id: int, owner: str = Form(""), criticality: str = Form("medium")):
    if criticality not in {"high", "medium", "low"}:
        return HTMLResponse("Некорректная критичность", status_code=400)
    db = session()
    item = db.get(Service, service_id)
    if not item:
        db.close()
        return HTMLResponse("Цель не найдена", status_code=404)
    item.owner = owner.strip() or None
    item.criticality = criticality
    db.add(item)
    db.commit()
    db.close()
    audit("SERVICE_UPDATED", {"service_id": service_id, "owner": item.owner, "criticality": criticality})
    return RedirectResponse("/targets", status_code=303)


@app.post("/api/scan")
def api_scan():
    item = run_scan_background(triggered_by="ui")
    return {"id": item.id, "status": "running", "processed": 0, "total": item.total}


@app.post("/scans/start")
def start_scan():
    item = run_scan_background(triggered_by="ui")
    return RedirectResponse(f"/scans/{item.id}", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", dashboard_data())


@app.get("/certificates", response_class=HTMLResponse)
def certificates(
    request: Request,
    status: str | None = None,
    q: str | None = None,
    owner: str | None = None,
    issuer: str | None = None,
    risk_level: str | None = None,
    days_max: str | None = None,
    sort: str = "days_left",
    dir: str = "asc",
):
    all_data = rows()
    owners = sorted({s.owner for s, _ in all_data if s.owner})
    issuers = sorted({r.issuer_cn for _, r in all_data if r.issuer_cn})
    filters = result_filters(status, q, owner, issuer, risk_level, days_max)
    data = rows(filters=filters, sort=sort, direction=dir)
    return templates.TemplateResponse(
        request,
        "certificates.html",
        {
            "rows": data,
            "status": status or "",
            "q": q or "",
            "owner": owner or "",
            "issuer": issuer or "",
            "risk_level": risk_level or "",
            "days_max": days_max or "",
            "owners": owners,
            "issuers": issuers,
            "sort": sort,
            "direction": dir,
        },
    )


@app.get("/certificates/{result_id}", response_class=HTMLResponse)
def certificate(request: Request, result_id: int):
    db = session()
    result = db.get(CertResult, result_id)
    service = db.get(Service, result.service_id) if result else None
    db.close()
    if not result or not service:
        return HTMLResponse("Не найдено", status_code=404)
    return templates.TemplateResponse(
        request,
        "certificate.html",
        {
            "service": service,
            "result": result,
            "findings": json_list(result.findings),
            "san_dns": json_list(result.san_dns),
            "san_ip": json_list(result.san_ip),
            "history": service_history(service.id),
        },
    )


def export_response(
    format: str = "csv",
    status: str | None = None,
    q: str | None = None,
    owner: str | None = None,
    issuer: str | None = None,
    risk_level: str | None = None,
    days_max: str | None = None,
):
    data = rows(
        filters=result_filters(status, q, owner, issuer, risk_level, days_max),
        sort="days_left",
        direction="asc",
    )
    audit("EXPORT", {"format": format, "status": status, "rows": len(data)})
    if format == "xlsx":
        return Response(
            export_xlsx(data),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=certificates.xlsx"},
        )
    if format == "html":
        return HTMLResponse(export_html(data))
    return Response(
        export_csv(data),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=certificates.csv"},
    )


@app.get("/export")
def export(
    format: str = Query("csv"),
    status: str | None = None,
    q: str | None = None,
    owner: str | None = None,
    issuer: str | None = None,
    risk_level: str | None = None,
    days_max: str | None = None,
):
    return export_response(format, status, q, owner, issuer, risk_level, days_max)


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    db = session()
    logs = list(db.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(500)))
    db.close()
    return templates.TemplateResponse(request, "audit.html", {"logs": logs})


@app.get("/notifications", response_class=HTMLResponse)
def notifications(request: Request):
    db = session()
    logs = list(db.exec(select(NotificationLog).order_by(NotificationLog.id.desc()).limit(500)))
    db.close()
    return templates.TemplateResponse(request, "notifications.html", {"logs": logs})


@app.post("/api/notifications/test")
def notification_test():
    return send_test()


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html", {"values": current_settings()})


@app.post("/settings", response_class=HTMLResponse)
def save_settings(
    request: Request,
    info_days: int = Form(...),
    warning_days: int = Form(...),
    critical_days: int = Form(...),
    notify_thresholds: str = Form("60,30,14,7,1"),
    schedule_hours: int = Form(0),
):
    ok, message, values = apply_settings(
        info_days, warning_days, critical_days, notify_thresholds, schedule_hours
    )
    if not ok:
        return templates.TemplateResponse(
            request,
            "settings.html",
            {"values": values, "error": message},
            status_code=400,
        )
    update_scheduler(_scheduler, schedule_hours)
    return templates.TemplateResponse(
        request,
        "settings.html",
        {"values": values, "message": message},
    )


@app.post("/settings/test")
def settings_test_notification():
    send_test()
    return RedirectResponse("/notifications", status_code=303)


@app.post("/notifications/test")
def notifications_test():
    send_test()
    return RedirectResponse("/notifications", status_code=303)


@app.get("/scans", response_class=HTMLResponse)
def scans(request: Request):
    db = session()
    items = list(db.exec(select(Scan).order_by(Scan.id.desc())))
    db.close()
    return templates.TemplateResponse(request, "scans.html", {"items": items})


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: int):
    db = session()
    item = db.get(Scan, scan_id)
    db.close()
    if not item:
        return HTMLResponse("Скан не найден", status_code=404)
    return templates.TemplateResponse(
        request,
        "scan.html",
        {"item": item, "summary": scan_summary(scan_id) if item.status == "done" else None},
    )


@app.get("/api/scans")
def api_scans():
    db = session()
    items = list(db.exec(select(Scan).order_by(Scan.id.desc())))
    db.close()
    return [
        {
            "id": x.id,
            "status": x.status,
            "total": x.total,
            "processed": x.processed,
            "started_at": x.started_at,
            "finished_at": x.finished_at,
        }
        for x in items
    ]


@app.get("/api/certificates")
def api_certificates(status: str | None = None):
    data = rows()
    return [
        {
            "id": r.id,
            "host": s.host,
            "port": s.port,
            "owner": s.owner,
            "status": r.status,
            "days_left": r.days_left,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
        }
        for s, r in data
        if not status or r.status == status
    ]


@app.get("/api/dashboard")
def api_dashboard():
    data = dashboard_data()
    return {
        "total": data["total"],
        "statuses": data["cards"],
        "risks": data["risks"],
        "has_scan": data["has_scan"],
        "health_score": data.get("health_score", 100),
        "findings_summary": data.get("findings_summary", {}),
        "reachable_count": data.get("reachable_count", data["total"]),
        "unreachable_count": data.get("unreachable_count", 0),
        "reachability_rate": data.get("reachability_rate", 100.0),
    }


@app.get("/api/services")
def api_services():
    db = session()
    items = list(db.exec(select(Service).order_by(Service.host)))
    db.close()
    return [
        {
            "id": x.id,
            "host": x.host,
            "port": x.port,
            "service_name": x.service_name,
            "owner": x.owner,
            "criticality": x.criticality,
        }
        for x in items
    ]


@app.get("/api/audit")
def api_audit():
    db = session()
    items = list(db.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(500)))
    db.close()
    return [
        {
            "id": x.id,
            "ts": x.ts,
            "actor": x.actor,
            "action": x.action,
            "details": x.details if isinstance(x.details, dict) else json.loads(x.details),
        }
        for x in items
    ]


@app.get("/api/notifications")
def api_notifications():
    db = session()
    items = list(db.exec(select(NotificationLog).order_by(NotificationLog.id.desc()).limit(500)))
    db.close()
    return [
        {
            "id": x.id,
            "service_id": x.service_id,
            "threshold": x.threshold,
            "channel": x.channel,
            "success": x.success,
            "message": x.message,
            "sent_at": x.sent_at,
        }
        for x in items
    ]


@app.get("/api/certificates/{result_id}")
def api_certificate(result_id: int):
    db = session()
    item = db.get(CertResult, result_id)
    if not item:
        db.close()
        return Response(status_code=404)
    service = db.get(Service, item.service_id)
    db.close()
    return {
        "id": item.id,
        "host": service.host,
        "port": service.port,
        "subject_cn": item.subject_cn,
        "issuer_cn": item.issuer_cn,
        "status": item.status,
        "days_left": item.days_left,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "findings": json_list(item.findings),
    }


@app.post("/api/services/{service_id}")
def update_service(service_id: int, owner: str = Form(""), criticality: str = Form("medium")):
    if criticality not in {"high", "medium", "low"}:
        return Response(status_code=400)
    db = session()
    item = db.get(Service, service_id)
    if not item:
        db.close()
        return Response(status_code=404)
    item.owner = owner or None
    item.criticality = criticality
    db.add(item)
    db.commit()
    db.close()
    audit("SERVICE_UPDATED", {"service_id": service_id})
    return {"status": "ok"}


@app.post("/api/targets/import")
async def api_targets_import(file: UploadFile | None = File(None), target_text: str = Form("")):
    if file is not None:
        report = import_targets(await file.read(), file.filename or "targets.txt")
    else:
        report = import_targets(target_text.encode("utf-8"), "targets.txt")
    return {
        "added": report.added,
        "updated": report.updated,
        "duplicates": report.duplicates,
        "invalid": report.invalid,
    }


@app.post("/api/scans")
def api_scans_start():
    item = run_scan_background(triggered_by="ui")
    return {"id": item.id, "status": "running", "processed": 0, "total": item.total}


@app.get("/api/scans/{scan_id}")
def api_scan_detail(scan_id: int):
    db = session()
    item = db.get(Scan, scan_id)
    db.close()
    if not item:
        return JSONResponse({"error": "not found"}, status_code=404)
    return {
        "id": item.id,
        "status": item.status,
        "total": item.total,
        "processed": item.processed,
        "started_at": item.started_at,
        "finished_at": item.finished_at,
        "triggered_by": item.triggered_by,
        "summary": scan_summary(scan_id) if item.status == "done" else None,
    }


@app.get("/api/results")
def api_results(
    status: str | None = None,
    q: str | None = None,
    owner: str | None = None,
    issuer: str | None = None,
    risk_level: str | None = None,
    days_max: str | None = None,
    sort: str = "days_left",
    dir: str = "asc",
):
    data = rows(
        filters=result_filters(status, q, owner, issuer, risk_level, days_max),
        sort=sort,
        direction=dir,
    )
    return [
        {
            "id": r.id,
            "host": s.host,
            "port": s.port,
            "service_name": s.service_name,
            "owner": s.owner,
            "status": r.status,
            "days_left": r.days_left,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "issuer_cn": r.issuer_cn,
        }
        for s, r in data
    ]


@app.get("/api/results/{result_id}")
def api_result_detail(result_id: int):
    return api_certificate(result_id)


@app.get("/api/settings")
def api_get_settings():
    return current_settings()


@app.put("/api/settings")
def api_put_settings(payload: dict):
    notify = payload.get("notify_thresholds", "60,30,14,7,1")
    if isinstance(notify, list):
        notify = ",".join(str(item) for item in notify)
    ok, message, values = apply_settings(
        int(payload.get("info_days", 60)),
        int(payload.get("warning_days", 30)),
        int(payload.get("critical_days", 14)),
        str(notify),
        int(payload.get("schedule_hours", 0)),
    )
    if not ok:
        return JSONResponse({"error": message}, status_code=400)
    update_scheduler(_scheduler, int(payload.get("schedule_hours", 0)))
    return {"ok": True, "message": message, "values": values}


@app.patch("/api/services/{service_id}")
def api_patch_service(service_id: int, payload: dict):
    db = session()
    item = db.get(Service, service_id)
    if not item:
        db.close()
        return JSONResponse({"error": "not found"}, status_code=404)
    owner = payload.get("owner", item.owner)
    criticality = payload.get("criticality", item.criticality)
    if criticality not in {"high", "medium", "low"}:
        db.close()
        return JSONResponse({"error": "invalid criticality"}, status_code=400)
    item.owner = (owner or "").strip() or None
    item.criticality = criticality
    db.add(item)
    db.commit()
    db.close()
    audit("SERVICE_UPDATED", {"service_id": service_id, "owner": item.owner, "criticality": criticality})
    return {"id": service_id, "owner": item.owner, "criticality": item.criticality}


@app.get("/api/export")
def api_export(
    format: str = Query("csv"),
    status: str | None = None,
    q: str | None = None,
    owner: str | None = None,
    issuer: str | None = None,
    risk_level: str | None = None,
    days_max: str | None = None,
):
    return export_response(format, status, q, owner, issuer, risk_level, days_max)
