import json
from contextlib import asynccontextmanager
from threading import Thread
from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import select
from ..audit import audit
from ..db import session
from ..export.csv_export import export_csv
from ..export.html_export import export_html
from ..export.xlsx_export import export_xlsx
from ..models import AuditLog, CertResult, Service, NotificationLog, Setting, Scan
from ..services import import_targets, run_scan, recompute_latest
from ..notify.service import send_test
from ..scheduler import start_scheduler
from ..config import ROOT, load_config

_scheduler = None

@asynccontextmanager
async def lifespan(app):
    global _scheduler
    if _scheduler is None:
        db=session(); saved=db.get(Setting,"schedule_hours"); db.close(); hours=int(saved.value) if saved else load_config().get("scan",{}).get("schedule_hours",0); _scheduler=start_scheduler(hours)
    yield
    if _scheduler: _scheduler.shutdown(wait=False); _scheduler=None

app = FastAPI(title="Certificate Radar", lifespan=lifespan)
WEB_ROOT=ROOT/"radar"/"web"
templates=Jinja2Templates(directory=str(WEB_ROOT/"templates"))
app.mount("/static",StaticFiles(directory=str(WEB_ROOT/"static")),name="static")

@app.get("/health")
def health(): return {"status": "ok"}

def rows():
    db=session(); latest=db.exec(select(Scan).where(Scan.status == "done").order_by(Scan.id.desc())).first()
    result=list(db.exec(select(CertResult).where(CertResult.scan_id == latest.id))) if latest else []
    services={s.id:s for s in db.exec(select(Service))}; db.close(); return [(services[x.service_id], x) for x in result]

@app.post("/api/import")
async def api_import(file: UploadFile = File(...)):
    report=import_targets(await file.read(), file.filename or "targets.txt"); return {"added":report.added,"updated":report.updated,"duplicates":report.duplicates,"invalid":report.invalid}

@app.get("/targets", response_class=HTMLResponse)
def targets_page(request: Request):
    db=session(); items=list(db.exec(select(Service).order_by(Service.host))); db.close()
    return templates.TemplateResponse(request,"targets.html",{"items":items})

@app.post("/targets/import", response_class=HTMLResponse)
def targets_import(target_text: str = Form(...)):
    report=import_targets(target_text.encode("utf-8"), "targets.txt")
    errors="; ".join(f"строка {x[0]}: {x[2]}" for x in report.invalid)
    return f"<p>Добавлено: {report.added}; Обновлено: {report.updated}; Дубликаты: {report.duplicates}; Ошибки: {len(report.invalid)}</p><p>{errors}</p><a href='/targets'>Назад</a>"

@app.post("/targets/upload", response_class=HTMLResponse)
async def targets_upload(file: UploadFile = File(...)):
    report=import_targets(await file.read(),file.filename or "targets.txt")
    errors="; ".join(f"строка {x[0]}: {x[2]}" for x in report.invalid)
    return f"<p>Добавлено: {report.added}; Обновлено: {report.updated}; Дубликаты: {report.duplicates}; Ошибки: {len(report.invalid)}</p><p>{errors}</p><a href='/targets'>Назад</a>"

@app.post("/api/scan")
def api_scan():
    db=session(); item=Scan(total=len(list(db.exec(select(Service)))), triggered_by="ui"); db.add(item); db.commit(); db.refresh(item); db.close()
    def worker(): run_scan("ui", item.id)
    Thread(target=worker, daemon=True).start(); return {"id":item.id,"status":"running","processed":0,"total":item.total}

@app.post("/scans/start")
def start_scan():
    db=session(); item=Scan(total=len(list(db.exec(select(Service)))),triggered_by="ui"); db.add(item); db.commit(); db.refresh(item); db.close()
    Thread(target=lambda:run_scan("ui",item.id),daemon=True).start()
    return RedirectResponse(f"/scans/{item.id}",status_code=303)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    data=rows(); cards={x:sum(r.status==x for _,r in data) for x in ["OK","Information","Warning","Critical","Expired","Unreachable"]}
    nearest=sorted([(s,r) for s,r in data if r.days_left is not None],key=lambda x:x[1].days_left)[:10]
    return templates.TemplateResponse(request,"dashboard.html",{"cards":cards,"nearest":nearest})

@app.get("/certificates", response_class=HTMLResponse)
def certificates(request: Request, status: str | None = None, q: str | None = None, owner: str | None = None, issuer: str | None = None, sort: str = "days_left", dir: str = "asc"):
    data=rows(); data=[(s,r) for s,r in data if (not status or r.status==status) and (not owner or s.owner==owner) and (not issuer or r.issuer_cn==issuer) and (not q or q.lower() in (s.host+" "+(s.service_name or "")).lower())]
    key={"host":lambda x:x[0].host,"owner":lambda x:x[0].owner or "","issuer":lambda x:x[1].issuer_cn or "","risk":lambda x:x[1].risk_score if x[1].risk_score is not None else -1,"days_left":lambda x:x[1].days_left if x[1].days_left is not None else 10**9}.get(sort,lambda x:x[1].days_left or 10**9)
    data.sort(key=key, reverse=dir == "desc")
    return templates.TemplateResponse(request,"certificates.html",{"rows":data,"status":status or "","q":q or ""})

@app.get("/certificates/{result_id}", response_class=HTMLResponse)
def certificate(request: Request, result_id: int):
    db=session(); result=db.get(CertResult,result_id); service=db.get(Service,result.service_id) if result else None; db.close()
    if not result: return HTMLResponse("Не найдено", status_code=404)
    findings=json.loads(result.findings or "[]")
    return templates.TemplateResponse(request,"certificate.html",{"service":service,"result":result,"findings":findings,"san_dns":json.loads(result.san_dns),"san_ip":json.loads(result.san_ip)})

@app.get("/export")
def export(format: str = Query("csv"), status: str | None = None, q: str | None = None, owner: str | None = None, issuer: str | None = None):
    data=[(s,r) for s,r in rows() if (not status or r.status==status) and (not owner or s.owner==owner) and (not issuer or r.issuer_cn==issuer) and (not q or q.lower() in (s.host+" "+(s.service_name or "")).lower())]; audit("EXPORT", {"format":format,"status":status,"rows":len(data)})
    if format == "xlsx": return Response(export_xlsx(data), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if format == "html": return HTMLResponse(export_html(data))
    return Response(export_csv(data), media_type="text/csv; charset=utf-8", headers={"Content-Disposition":"attachment; filename=certificates.csv"})

@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    db=session(); logs=list(db.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(500))); db.close(); return templates.TemplateResponse(request,"audit.html",{"logs":logs})

@app.get("/notifications", response_class=HTMLResponse)
def notifications(request: Request):
    db=session(); logs=list(db.exec(select(NotificationLog).order_by(NotificationLog.id.desc()).limit(500))); db.close(); return templates.TemplateResponse(request,"notifications.html",{"logs":logs})

@app.post("/api/notifications/test")
def notification_test(): return send_test()

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    db=session(); values={x.key:x.value for x in db.exec(select(Setting))}; db.close(); return templates.TemplateResponse(request,"settings.html",{"values":values})

@app.post("/settings", response_class=HTMLResponse)
def save_settings(info_days: int = Form(...), warning_days: int = Form(...), critical_days: int = Form(...), notify_thresholds: str = Form("60,30,14,7,1"), schedule_hours: int = Form(0)):
    if not info_days > warning_days > critical_days >= 0: return HTMLResponse("Ошибка: требуется info > warning > critical >= 0", status_code=400)
    try: parsed=sorted({int(x.strip()) for x in notify_thresholds.split(",") if x.strip()},reverse=True)
    except ValueError: return HTMLResponse("Ошибка: пороги уведомлений должны быть числами",status_code=400)
    if not parsed or min(parsed) < 0 or schedule_hours < 0: return HTMLResponse("Ошибка: значения должны быть неотрицательными",status_code=400)
    db=session()
    for key,value in {"info_days":info_days,"warning_days":warning_days,"critical_days":critical_days,"notify_thresholds":",".join(map(str,parsed)),"schedule_hours":schedule_hours}.items():
        item=db.get(Setting,key) or Setting(key=key); item.value=str(value); db.add(item)
    db.commit(); db.close(); recompute_latest(); audit("SETTINGS_UPDATED", {"info_days":info_days,"warning_days":warning_days,"critical_days":critical_days,"notify_thresholds":parsed,"schedule_hours":schedule_hours}); return "<p>Настройки сохранены и результаты пересчитаны. Новое расписание применяется после перезапуска.</p><a href='/settings'>Назад</a>"

@app.get("/scans", response_class=HTMLResponse)
def scans(request: Request):
    db=session(); items=list(db.exec(select(Scan).order_by(Scan.id.desc()))); db.close(); return templates.TemplateResponse(request,"scans.html",{"items":items})

@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: int):
    db=session(); item=db.get(Scan,scan_id); db.close()
    if not item: return HTMLResponse("Скан не найден",status_code=404)
    return templates.TemplateResponse(request,"scan.html",{"item":item})

@app.get("/api/scans")
def api_scans():
    db=session(); items=list(db.exec(select(Scan).order_by(Scan.id.desc()))); db.close(); return [{"id":x.id,"status":x.status,"total":x.total,"processed":x.processed,"started_at":x.started_at,"finished_at":x.finished_at} for x in items]

@app.get("/api/certificates")
def api_certificates(status: str | None = None):
    data=rows(); return [{"id":r.id,"host":s.host,"port":s.port,"owner":s.owner,"status":r.status,"days_left":r.days_left,"risk_score":r.risk_score,"risk_level":r.risk_level} for s,r in data if not status or r.status == status]

@app.get("/api/dashboard")
def api_dashboard():
    data=rows(); statuses=["OK","Information","Warning","Critical","Expired","Unreachable"]
    return {"total":len(data),"statuses":{status:sum(item.status == status for _,item in data) for status in statuses}}

@app.get("/api/services")
def api_services():
    db=session(); items=list(db.exec(select(Service).order_by(Service.host))); db.close()
    return [{"id":x.id,"host":x.host,"port":x.port,"service_name":x.service_name,"owner":x.owner,"criticality":x.criticality} for x in items]

@app.get("/api/audit")
def api_audit():
    db=session(); items=list(db.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(500))); db.close()
    return [{"id":x.id,"ts":x.ts,"actor":x.actor,"action":x.action,"details":json.loads(x.details)} for x in items]

@app.get("/api/notifications")
def api_notifications():
    db=session(); items=list(db.exec(select(NotificationLog).order_by(NotificationLog.id.desc()).limit(500))); db.close()
    return [{"id":x.id,"service_id":x.service_id,"threshold":x.threshold,"channel":x.channel,"success":x.success,"message":x.message,"sent_at":x.sent_at} for x in items]

@app.get("/api/certificates/{result_id}")
def api_certificate(result_id: int):
    db=session(); item=db.get(CertResult,result_id)
    if not item: db.close(); return Response(status_code=404)
    service=db.get(Service,item.service_id); db.close(); return {"id":item.id,"host":service.host,"port":service.port,"subject_cn":item.subject_cn,"issuer_cn":item.issuer_cn,"status":item.status,"days_left":item.days_left,"risk_score":item.risk_score,"risk_level":item.risk_level,"findings":json.loads(item.findings)}

@app.post("/api/services/{service_id}")
def update_service(service_id: int, owner: str = Form(""), criticality: str = Form("medium")):
    if criticality not in {"high","medium","low"}: return Response(status_code=400)
    db=session(); item=db.get(Service,service_id)
    if not item: db.close(); return Response(status_code=404)
    item.owner=owner or None; item.criticality=criticality; db.add(item); db.commit(); db.close(); audit("SERVICE_UPDATED", {"service_id":service_id}); return {"status":"ok"}
