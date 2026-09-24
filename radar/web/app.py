import json
from fastapi import FastAPI, File, UploadFile, Query, Form
from fastapi.responses import HTMLResponse, Response
from sqlmodel import select
from ..audit import audit
from ..db import session
from ..export.csv_export import export_csv
from ..export.html_export import export_html
from ..export.xlsx_export import export_xlsx
from ..models import AuditLog, CertResult, Service, NotificationLog, Setting, Scan
from ..services import import_targets, run_scan

app = FastAPI(title="Certificate Radar")

@app.get("/health")
def health(): return {"status": "ok"}

def rows():
    db=session(); result=list(db.exec(select(CertResult))); services={s.id:s for s in db.exec(select(Service))}; db.close(); return [(services[x.service_id], x) for x in result]

@app.post("/api/import")
async def api_import(file: UploadFile = File(...)):
    report=import_targets(await file.read(), file.filename or "targets.txt"); return {"added":report.added,"updated":report.updated,"duplicates":report.duplicates,"invalid":report.invalid}

@app.post("/api/scan")
def api_scan():
    scan=run_scan("ui"); return {"id":scan.id,"status":scan.status,"processed":scan.processed,"total":scan.total}

@app.get("/", response_class=HTMLResponse)
def dashboard():
    data=rows(); cards={x:sum(r.status==x for _,r in data) for x in ["OK","Information","Warning","Critical","Expired","Unreachable"]}
    return "<h1>Certificate Radar</h1><nav><a href='/certificates'>Сертификаты</a> | <a href='/export?format=csv'>Экспорт CSV</a></nav><p>"+"; ".join(f"{k}: {v}" for k,v in cards.items())+"</p>"

@app.get("/certificates", response_class=HTMLResponse)
def certificates(status: str | None = None, q: str | None = None):
    data=rows(); data=[(s,r) for s,r in data if (not status or r.status==status) and (not q or q.lower() in (s.host+" "+(s.service_name or "")).lower())]
    body="".join(f"<tr><td><a href='/certificates/{r.id}'>{s.host}</a></td><td>{s.owner or 'не назначен'}</td><td>{r.status}</td><td>{r.days_left if r.days_left is not None else ''}</td><td>{r.risk_score or ''}</td></tr>" for s,r in data)
    return f"<h1>Сертификаты</h1><form>Статус <input name='status'> Поиск <input name='q'><button>Фильтр</button></form><table><tr><th>Хост</th><th>Владелец</th><th>Статус</th><th>Дни</th><th>Risk</th></tr>{body}</table>"

@app.get("/certificates/{result_id}", response_class=HTMLResponse)
def certificate(result_id: int):
    db=session(); result=db.get(CertResult,result_id); service=db.get(Service,result.service_id) if result else None; db.close()
    if not result: return HTMLResponse("Не найдено", status_code=404)
    findings=json.loads(result.findings or "[]"); items="".join(f"<li>{x.get('reason') or x['code']} — {x.get('recommendation','')}</li>" for x in findings)
    return f"<h1>{service.host}</h1><p>Статус: {result.status}; Risk: {result.risk_score or 'N/A'} ({result.risk_level})</p><p>CN: {result.subject_cn or ''}; Issuer: {result.issuer_cn or ''}</p><ul>{items}</ul>"

@app.get("/export")
def export(format: str = Query("csv")):
    data=rows(); audit("EXPORT", {"format":format})
    if format == "xlsx": return Response(export_xlsx(data), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if format == "html": return HTMLResponse(export_html(data))
    return Response(export_csv(data), media_type="text/csv; charset=utf-8", headers={"Content-Disposition":"attachment; filename=certificates.csv"})

@app.get("/audit", response_class=HTMLResponse)
def audit_page():
    db=session(); logs=list(db.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(500))); db.close(); return "<h1>Аудит</h1><pre>"+"\n".join(f"{x.ts} {x.action} {x.details}" for x in logs)+"</pre>"

@app.get("/notifications", response_class=HTMLResponse)
def notifications():
    db=session(); logs=list(db.exec(select(NotificationLog).order_by(NotificationLog.id.desc()).limit(500))); db.close(); return "<h1>Уведомления</h1><pre>"+"\n".join(f"{x.sent_at} {x.channel} threshold={x.threshold} {x.message}" for x in logs)+"</pre>"

@app.get("/settings", response_class=HTMLResponse)
def settings_page():
    db=session(); values={x.key:x.value for x in db.exec(select(Setting))}; db.close(); return f"<h1>Настройки</h1><form method='post'><label>Информационный порог <input name='info_days' value='{values.get('info_days','60')}'></label><label>Предупреждение <input name='warning_days' value='{values.get('warning_days','30')}'></label><label>Критический <input name='critical_days' value='{values.get('critical_days','14')}'></label><button>Сохранить</button></form>"

@app.post("/settings", response_class=HTMLResponse)
def save_settings(info_days: int = Form(...), warning_days: int = Form(...), critical_days: int = Form(...)):
    if not info_days > warning_days > critical_days >= 0: return HTMLResponse("Ошибка: требуется info > warning > critical >= 0", status_code=400)
    db=session()
    for key,value in {"info_days":info_days,"warning_days":warning_days,"critical_days":critical_days}.items():
        item=db.get(Setting,key) or Setting(key=key); item.value=str(value); db.add(item)
    db.commit(); db.close(); audit("SETTINGS_UPDATED", {"info_days":info_days,"warning_days":warning_days,"critical_days":critical_days}); return "<p>Настройки сохранены</p><a href='/settings'>Назад</a>"

@app.get("/scans", response_class=HTMLResponse)
def scans():
    db=session(); items=list(db.exec(select(Scan).order_by(Scan.id.desc()))); db.close(); body="".join(f"<tr><td>{x.id}</td><td>{x.started_at}</td><td>{x.status}</td><td>{x.processed}/{x.total}</td></tr>" for x in items)
    return f"<h1>История сканов</h1><table><tr><th>ID</th><th>Начало</th><th>Статус</th><th>Обработано</th></tr>{body}</table>"

@app.get("/api/scans")
def api_scans():
    db=session(); items=list(db.exec(select(Scan).order_by(Scan.id.desc()))); db.close(); return [{"id":x.id,"status":x.status,"total":x.total,"processed":x.processed,"started_at":x.started_at,"finished_at":x.finished_at} for x in items]

@app.get("/api/certificates")
def api_certificates(status: str | None = None):
    data=rows(); return [{"id":r.id,"host":s.host,"port":s.port,"owner":s.owner,"status":r.status,"days_left":r.days_left,"risk_score":r.risk_score,"risk_level":r.risk_level} for s,r in data if not status or r.status == status]
