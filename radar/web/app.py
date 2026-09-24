from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
from sqlmodel import select

from ..db import session
from ..models import CertResult
from ..services import import_targets, run_scan

app=FastAPI(title="Certificate Radar")
@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/api/import")
async def api_import(file: UploadFile=File(...)):
    r=import_targets(await file.read(), file.filename or "targets.txt"); return {"added":r.added,"updated":r.updated,"duplicates":r.duplicates,"invalid":r.invalid}
@app.post("/api/scan")
def api_scan():
    s=run_scan("ui"); return {"id":s.id,"status":s.status,"processed":s.processed,"total":s.total}
@app.get("/", response_class=HTMLResponse)
def dashboard():
    db=session(); rows=list(db.exec(select(CertResult))); db.close()
    cards={x:sum(r.status==x for r in rows) for x in ["OK","Information","Warning","Critical","Expired","Unreachable"]}
    return "<h1>Certificate Radar</h1><p>"+"; ".join(f"{k}: {v}" for k,v in cards.items())+"</p>"
