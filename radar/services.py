import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

from sqlmodel import select

from .analysis import analyze
from .config import load_config
from .db import session
from .models import CertResult, Scan, Service
from .scanner.tls import grab
from .targets.parser import parse_file
from .audit import audit
from .notify.service import notify_after_scan
from .models import Setting
from .checks.chain import chain_status


def import_targets(data, filename):
    report = parse_file(data, filename); db = session()
    for item in report.services:
        old = db.exec(select(Service).where(Service.host == item["host"], Service.port == item["port"])).first()
        if old:
            if item.get("owner") is not None: old.owner = item["owner"]
            if item.get("criticality") is not None: old.criticality = item["criticality"]
            report.updated += 1
        else: db.add(Service(**item)); report.added += 1
    db.commit(); db.close(); audit("IMPORT_TARGETS", {"added": report.added, "duplicates": report.duplicates}); return report

def run_scan(triggered_by="cli", existing_scan_id=None):
    db=session(); services=list(db.exec(select(Service)))
    scan=db.get(Scan, existing_scan_id) if existing_scan_id else Scan(total=len(services), triggered_by=triggered_by)
    if not existing_scan_id: db.add(scan); db.commit(); db.refresh(scan)
    audit("SCAN_STARTED",{"scan_id":scan.id,"triggered_by":triggered_by,"total":len(services)})
    cfg=load_config(); workers=cfg["scan"]["workers"]
    stored={x.key:int(x.value) for x in db.exec(select(Setting)) if x.key in {"info_days","warning_days","critical_days"}}
    thresholds={**cfg["thresholds"],**stored}
    def one(service): return service, grab(service.host, service.port, cfg["scan"]["timeout_sec"], overrides=cfg.get("dns_overrides"), extra_ca_files=cfg.get("trust",{}).get("extra_ca_files",[]))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(one, s) for s in services]
        for future in as_completed(futures):
            service, raw = future.result()
            result=analyze(raw, service, thresholds); db.add(CertResult(scan_id=scan.id, service_id=service.id, reachable=raw.reachable, error=raw.error, resolved_ip=raw.resolved_ip, leaf_pem=raw.leaf_pem, subject_cn=raw.subject_cn, san_dns=json.dumps(raw.san_dns or []), san_ip=json.dumps(raw.san_ip or []), issuer_cn=raw.issuer_cn, issuer_full=raw.issuer_full, serial=raw.serial, thumbprint_sha1=raw.thumbprint_sha1, thumbprint_sha256=raw.thumbprint_sha256, not_before=raw.not_before, not_after=raw.not_after, key_type=raw.key_type, key_size=raw.key_size, sig_hash=raw.sig_hash, tls_version=raw.tls_version, chain_verify_code=raw.chain_verify_code, chain_verify_message=raw.chain_verify_message, chain_status=chain_status(raw.chain_verify_code,result.get("self_signed",False)), days_left=result["days_left"], status=result["status"], hostname_match=result.get("hostname_match"), self_signed=result.get("self_signed"), weak_crypto=result.get("weak_crypto"), risk_score=result["risk_score"], risk_level=result["risk_level"], findings=json.dumps([f.__dict__ for f in result["findings"]], ensure_ascii=False))); scan.processed += 1
    scan.status="done"; scan.finished_at=datetime.now(UTC); db.add(scan); db.commit(); db.close(); notify_after_scan(scan.id); audit("SCAN_FINISHED", {"scan_id": scan.id, "processed": scan.processed}); return scan

def recompute_latest():
    db=session(); latest=db.exec(select(Scan).where(Scan.status == "done").order_by(Scan.id.desc())).first()
    if not latest: db.close(); return 0
    values={x.key:int(x.value) for x in db.exec(select(Setting)) if x.key in {"info_days","warning_days","critical_days"}}
    thresholds={"info_days":values.get("info_days",60),"warning_days":values.get("warning_days",30),"critical_days":values.get("critical_days",14)}; services={x.id:x for x in db.exec(select(Service))}; count=0
    for item in db.exec(select(CertResult).where(CertResult.scan_id == latest.id)):
        if not item.leaf_pem: continue
        from .scanner.tls import RawResult
        raw=RawResult(True, leaf_pem=item.leaf_pem, subject_cn=item.subject_cn, san_dns=json.loads(item.san_dns), san_ip=json.loads(item.san_ip), issuer_cn=item.issuer_cn, not_before=item.not_before, not_after=item.not_after, key_type=item.key_type, key_size=item.key_size, sig_hash=item.sig_hash, chain_verify_code=item.chain_verify_code, chain_verify_message=item.chain_verify_message)
        result=analyze(raw, services[item.service_id], thresholds); item.days_left=result["days_left"]; item.status=result["status"]; item.risk_score=result["risk_score"]; item.risk_level=result["risk_level"]; item.findings=json.dumps([x.__dict__ for x in result["findings"]], ensure_ascii=False); db.add(item); count += 1
    db.commit(); db.close(); audit("RECOMPUTE", {"count":count}); return count
