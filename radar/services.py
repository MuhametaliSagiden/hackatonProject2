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

def run_scan(triggered_by="cli"):
    db=session(); services=list(db.exec(select(Service))); scan=Scan(total=len(services), triggered_by=triggered_by); db.add(scan); db.commit(); db.refresh(scan)
    cfg=load_config(); workers=cfg["scan"]["workers"]
    def one(service): return service, grab(service.host, service.port, cfg["scan"]["timeout_sec"], overrides=cfg.get("dns_overrides"))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(one, s) for s in services]
        for future in as_completed(futures):
            service, raw = future.result()
            result=analyze(raw, service, cfg["thresholds"]); db.add(CertResult(scan_id=scan.id, service_id=service.id, reachable=raw.reachable, error=raw.error, resolved_ip=raw.resolved_ip, leaf_pem=raw.leaf_pem, subject_cn=raw.subject_cn, san_dns=json.dumps(raw.san_dns or []), san_ip=json.dumps(raw.san_ip or []), issuer_cn=raw.issuer_cn, issuer_full=raw.issuer_full, serial=raw.serial, thumbprint_sha1=raw.thumbprint_sha1, thumbprint_sha256=raw.thumbprint_sha256, not_before=raw.not_before, not_after=raw.not_after, key_type=raw.key_type, key_size=raw.key_size, sig_hash=raw.sig_hash, tls_version=raw.tls_version, days_left=result["days_left"], status=result["status"], risk_score=result["risk_score"], risk_level=result["risk_level"], findings=json.dumps([f.__dict__ for f in result["findings"]], ensure_ascii=False))); scan.processed += 1
    scan.status="done"; scan.finished_at=datetime.now(UTC); db.add(scan); db.commit(); db.close(); audit("SCAN_FINISHED", {"scan_id": scan.id, "processed": scan.processed}); return scan
