from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
import threading

from sqlmodel import select

from ..analysis import analyze
from ..audit import audit
from ..checks.chain import chain_status
from ..config import load_config
from ..db import session
from ..models import CertResult, Scan, Service
from ..notify.service import notify_after_scan
from .tls import RawResult, grab

_scan_lock = threading.Lock()


def is_scan_running() -> bool:
    if _scan_lock.locked():
        return True
    with session() as db:
        running = db.exec(select(Scan).where(Scan.status == "running")).first()
        return running is not None


def run_scan(scan_id: int | None = None, triggered_by: str = "cli") -> Scan:
    if not _scan_lock.acquire(blocking=False):
        raise RuntimeError("Скан уже выполняется")

    try:
        with session() as db:
            services = list(db.exec(select(Service)))
            if scan_id:
                scan = db.get(Scan, scan_id)
                if not scan:
                    scan = Scan(id=scan_id, total=len(services), triggered_by=triggered_by)
                    db.add(scan)
                    db.commit()
                    db.refresh(scan)
            else:
                scan = Scan(total=len(services), triggered_by=triggered_by)
                db.add(scan)
                db.commit()
                db.refresh(scan)
            actual_scan_id = scan.id

        audit(
            "SCAN_STARTED", {"scan_id": actual_scan_id, "triggered_by": triggered_by, "total": len(services)}
        )

        cfg = load_config()
        workers = max(1, int(cfg.get("scan", {}).get("workers", 32)))
        timeout = float(cfg.get("scan", {}).get("timeout_sec", 5))
        overrides = cfg.get("dns_overrides", {})
        extra_ca_files = cfg.get("trust", {}).get("extra_ca_files", [])
        thresholds = cfg.get("thresholds", {"info_days": 60, "warning_days": 30, "critical_days": 14})

        def process_target(srv: Service) -> tuple[Service, RawResult]:
            res = grab(
                srv.host,
                srv.port,
                timeout=timeout,
                overrides=overrides,
                extra_ca_files=extra_ca_files,
            )
            return srv, res

        processed_count = 0
        pending_results: list[CertResult] = []

        def persist_batch() -> None:
            nonlocal pending_results
            if not pending_results:
                return
            with session() as db:
                db.add_all(pending_results)
                curr_scan = db.get(Scan, actual_scan_id)
                if curr_scan:
                    curr_scan.processed += len(pending_results)
                    db.add(curr_scan)
                db.commit()
            pending_results = []

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(process_target, s): s for s in services}
                for future in as_completed(futures):
                    srv = futures[future]
                    try:
                        srv, raw = future.result()
                    except Exception as exc:
                        raw = RawResult(reachable=False, error=f"Ошибка сканирования: {exc}")

                    try:
                        analysis_res = analyze(raw, srv, thresholds)
                    except Exception as exc:
                        raw = RawResult(reachable=False, error=f"Ошибка анализа: {exc}")
                        analysis_res = analyze(raw, srv, thresholds)

                    findings_data = [
                        f.__dict__ if hasattr(f, "__dict__") else f for f in analysis_res["findings"]
                    ]

                    cert_result = CertResult(
                        scan_id=actual_scan_id,
                        service_id=srv.id,
                        reachable=raw.reachable,
                        error=raw.error,
                        resolved_ip=raw.resolved_ip,
                        leaf_pem=raw.leaf_pem,
                        subject_cn=raw.subject_cn,
                        san_dns=raw.san_dns or [],
                        san_ip=raw.san_ip or [],
                        issuer_cn=raw.issuer_cn,
                        issuer_full=raw.issuer_full,
                        serial=raw.serial,
                        thumbprint_sha1=raw.thumbprint_sha1,
                        thumbprint_sha256=raw.thumbprint_sha256,
                        not_before=raw.not_before,
                        not_after=raw.not_after,
                        key_type=raw.key_type,
                        key_size=raw.key_size,
                        sig_hash=raw.sig_hash,
                        tls_version=raw.tls_version,
                        chain_verify_code=raw.chain_verify_code,
                        chain_verify_message=raw.chain_verify_message,
                        chain_status=chain_status(
                            raw.chain_verify_code, analysis_res.get("self_signed", False)
                        ),
                        days_left=analysis_res["days_left"],
                        status=analysis_res["status"],
                        hostname_match=analysis_res.get("hostname_match"),
                        self_signed=analysis_res.get("self_signed"),
                        weak_crypto=analysis_res.get("weak_crypto"),
                        risk_score=analysis_res["risk_score"],
                        risk_level=analysis_res["risk_level"],
                        findings=findings_data,
                    )

                    pending_results.append(cert_result)
                    processed_count += 1
                    if len(pending_results) >= 16:
                        persist_batch()

            persist_batch()

            with session() as db:
                curr_scan = db.get(Scan, actual_scan_id)
                curr_scan.status = "done"
                curr_scan.finished_at = datetime.now(UTC)
                db.add(curr_scan)
                db.commit()
                db.refresh(curr_scan)
                final_scan = curr_scan

            notify_after_scan(actual_scan_id)
            audit(
                "SCAN_FINISHED", {"scan_id": actual_scan_id, "status": "done", "processed": processed_count}
            )
            return final_scan

        except Exception as exc:
            with session() as db:
                curr_scan = db.get(Scan, actual_scan_id)
                if curr_scan:
                    curr_scan.status = "failed"
                    curr_scan.finished_at = datetime.now(UTC)
                    db.add(curr_scan)
                    db.commit()
            audit(
                "SCAN_FINISHED",
                {
                    "scan_id": actual_scan_id,
                    "status": "failed",
                    "error": str(exc),
                    "processed": processed_count,
                },
            )
            raise

    finally:
        _scan_lock.release()
