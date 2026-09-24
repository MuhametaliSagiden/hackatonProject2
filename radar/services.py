import threading
from typing import Any

from sqlmodel import select

from .analysis import analyze
from .audit import audit
from .checks.chain import chain_status
from .config import load_config
from .db import session
from .models import CertResult, Scan, Service, Setting
from .scanner.engine import run_scan as engine_run_scan
from .scanner.tls import RawResult
from .targets.parser import ImportReport, parse_file

STATUSES = ["OK", "Information", "Warning", "Critical", "Expired", "Unreachable"]
RISK_LEVELS = ["Critical", "High", "Medium", "Low"]


def import_targets(data: bytes, filename: str) -> ImportReport:
    report = parse_file(data, filename)
    with session() as db:
        for item in report.services:
            old = db.exec(
                select(Service).where(
                    Service.host == item["host"],
                    Service.port == item["port"],
                )
            ).first()
            if old:
                if item.get("owner") is not None:
                    old.owner = item["owner"]
                if item.get("criticality") is not None:
                    old.criticality = item["criticality"]
                db.add(old)
                report.updated += 1
            else:
                db.add(Service(**item))
                report.added += 1
        db.commit()
    audit(
        "IMPORT_TARGETS",
        {"added": report.added, "duplicates": report.duplicates, "invalid": len(report.invalid)},
    )
    return report


def create_scan(triggered_by: str = "ui") -> Scan:
    with session() as db:
        services_count = len(list(db.exec(select(Service))))
        scan = Scan(total=services_count, triggered_by=triggered_by)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan


def run_scan(triggered_by: str = "cli", existing_scan_id: int | None = None) -> Scan:
    return engine_run_scan(scan_id=existing_scan_id, triggered_by=triggered_by)


def run_scan_background(scan_id: int | None = None, triggered_by: str = "ui") -> Scan:
    scan = db_scan = None
    if scan_id is None:
        scan = create_scan(triggered_by=triggered_by)
        scan_id = scan.id
    else:
        with session() as db:
            db_scan = db.get(Scan, scan_id)
        scan = db_scan

    thread = threading.Thread(
        target=engine_run_scan,
        kwargs={"scan_id": scan_id, "triggered_by": triggered_by},
        daemon=True,
    )
    thread.start()
    return scan


def latest_results(
    filters: dict[str, Any] | None = None,
    sort: str = "days_left",
    direction: str = "asc",
) -> list[tuple[Service, CertResult]]:
    filters = filters or {}
    with session() as db:
        latest = db.exec(select(Scan).where(Scan.status == "done").order_by(Scan.id.desc())).first()
        if not latest:
            return []
        results = list(db.exec(select(CertResult).where(CertResult.scan_id == latest.id)))
        services = {s.id: s for s in db.exec(select(Service))}

    rows = []
    for r in results:
        s = services.get(r.service_id)
        if not s:
            continue

        # Status filter
        status_filter = filters.get("status")
        if status_filter:
            if isinstance(status_filter, (list, set, tuple)):
                if r.status not in status_filter:
                    continue
            elif r.status != status_filter:
                continue

        # Owner filter
        owner_filter = filters.get("owner")
        if owner_filter and s.owner != owner_filter:
            continue

        # Issuer filter
        issuer_filter = filters.get("issuer")
        if issuer_filter and r.issuer_cn != issuer_filter:
            continue

        # Risk level filter
        risk_level_filter = filters.get("risk_level")
        if risk_level_filter and r.risk_level != risk_level_filter:
            continue

        # Days max filter
        days_max = filters.get("days_max")
        if days_max is not None and days_max != "":
            try:
                max_d = int(days_max)
                if r.days_left is None or r.days_left > max_d:
                    continue
            except (ValueError, TypeError):
                pass

        # Text search q (service_name and host)
        q = filters.get("q")
        if q:
            target_str = f"{s.host} {s.service_name or ''}".lower()
            if q.lower() not in target_str:
                continue

        rows.append((s, r))

    sort_keys = {
        "host": lambda x: x[0].host.lower(),
        "service": lambda x: (x[0].service_name or "").lower(),
        "owner": lambda x: (x[0].owner or "").lower(),
        "issuer": lambda x: (x[1].issuer_cn or "").lower(),
        "risk": lambda x: x[1].risk_score if x[1].risk_score is not None else -1,
        "days_left": lambda x: x[1].days_left if x[1].days_left is not None else 10**9,
        "not_after": lambda x: x[1].not_after.timestamp() if x[1].not_after is not None else 10**18,
        "status": lambda x: x[1].status,
    }
    key_fn = sort_keys.get(sort, lambda x: x[1].days_left if x[1].days_left is not None else 10**9)
    rows.sort(key=key_fn, reverse=(direction == "desc"))
    return rows


def latest_done_scan() -> Scan | None:
    with session() as db:
        return db.exec(select(Scan).where(Scan.status == "done").order_by(Scan.id.desc())).first()


def dashboard_data() -> dict[str, Any]:
    data = latest_results()
    scan = latest_done_scan()
    cards = {name: sum(result.status == name for _, result in data) for name in STATUSES}
    risks = {name: sum(result.risk_level == name for _, result in data) for name in RISK_LEVELS}
    nearest = [(service, result) for service, result in data if result.days_left is not None]
    nearest.sort(key=lambda item: item[1].days_left)
    attention = [(service, result) for service, result in data if result.risk_level in {"Critical", "High"}]
    attention.sort(key=lambda item: item[1].risk_score or 0, reverse=True)
    total = len(data)
    segments = [
        (name, cards[name], round(100 * cards[name] / total, 1) if total else 0.0) for name in STATUSES
    ]
    reachable_count = sum(bool(result.reachable) for _, result in data)
    unreachable_count = total - reachable_count
    reachability_rate = round(100 * reachable_count / total, 1) if total else 0.0
    if total:
        avg_penalty = sum(result.risk_score or 60 for _, result in data) / total
        health_score = max(0, min(100, round(100 - avg_penalty)))
    else:
        health_score = 100

    findings_summary = {
        "chain_errors": sum(
            1
            for _, r in data
            if r.chain_status == "untrusted"
            or any(isinstance(f, dict) and f.get("code") == "CHAIN_ERROR" for f in (r.findings or []))
        ),
        "hostname_mismatches": sum(
            1
            for _, r in data
            if r.hostname_match is False
            or any(isinstance(f, dict) and f.get("code") == "HOSTNAME_MISMATCH" for f in (r.findings or []))
        ),
        "weak_crypto": sum(
            1
            for _, r in data
            if r.weak_crypto is True
            or any(isinstance(f, dict) and f.get("code") in ("WEAK_KEY", "WEAK_SIGNATURE") for f in (r.findings or []))
        ),
        "self_signed": sum(
            1
            for _, r in data
            if r.self_signed is True
            or any(isinstance(f, dict) and f.get("code") == "SELF_SIGNED" for f in (r.findings or []))
        ),
        "no_owner": sum(1 for s, _ in data if not s.owner),
    }

    return {
        "has_scan": scan is not None,
        "last_scan": scan,
        "cards": cards,
        "risks": risks,
        "nearest": nearest[:10],
        "attention": attention,
        "segments": segments,
        "total": total,
        "health_score": health_score,
        "findings_summary": findings_summary,
        "reachable_count": reachable_count,
        "unreachable_count": unreachable_count,
        "reachability_rate": reachability_rate,
    }


def scan_summary(scan_id: int) -> dict[str, int]:
    with session() as db:
        results = list(db.exec(select(CertResult).where(CertResult.scan_id == scan_id)))
    return {name: sum(item.status == name for item in results) for name in STATUSES}


def service_history(service_id: int) -> list[tuple[Scan, CertResult]]:
    with session() as db:
        results = list(
            db.exec(select(CertResult).where(CertResult.service_id == service_id).order_by(CertResult.scan_id.desc()))
        )
        scans = {item.id: item for item in db.exec(select(Scan))}
    return [(scans[item.scan_id], item) for item in results if item.scan_id in scans]


def current_settings() -> dict[str, Any]:
    with session() as db:
        stored = {item.key: item.value for item in db.exec(select(Setting))}
    cfg = load_config(override_from_db=False)
    values = {
        "info_days": cfg["thresholds"]["info_days"],
        "warning_days": cfg["thresholds"]["warning_days"],
        "critical_days": cfg["thresholds"]["critical_days"],
        "notify_thresholds": ",".join(str(item) for item in cfg["notify_thresholds"]),
        "schedule_hours": cfg["scan"]["schedule_hours"],
    }
    values.update({key: value for key, value in stored.items() if value is not None})
    return values


def apply_settings(
    info_days: int,
    warning_days: int,
    critical_days: int,
    notify_thresholds: str,
    schedule_hours: int,
) -> tuple[bool, str, dict[str, Any]]:
    values = current_settings()
    if not info_days > warning_days > critical_days >= 0:
        return False, "Ошибка: требуется info > warning > critical >= 0", values
    try:
        parsed = sorted({int(item.strip()) for item in notify_thresholds.split(",") if item.strip()}, reverse=True)
    except ValueError:
        return False, "Ошибка: пороги уведомлений должны быть числами", values
    if not parsed or min(parsed) < 0 or schedule_hours < 0:
        return False, "Ошибка: значения должны быть неотрицательными", values
    with session() as db:
        for key, value in {
            "info_days": info_days,
            "warning_days": warning_days,
            "critical_days": critical_days,
            "notify_thresholds": ",".join(map(str, parsed)),
            "schedule_hours": schedule_hours,
        }.items():
            item = db.get(Setting, key) or Setting(key=key)
            item.value = str(value)
            db.add(item)
        db.commit()
    recompute_latest()
    audit(
        "SETTINGS_UPDATED",
        {
            "info_days": info_days,
            "warning_days": warning_days,
            "critical_days": critical_days,
            "notify_thresholds": parsed,
            "schedule_hours": schedule_hours,
        },
    )
    return True, "Настройки сохранены, результаты пересчитаны и расписание обновлено.", current_settings()


def recompute_latest() -> int:
    with session() as db:
        latest = db.exec(select(Scan).where(Scan.status == "done").order_by(Scan.id.desc())).first()
        if not latest:
            return 0

        cfg = load_config()
        thresholds = cfg.get("thresholds", {"info_days": 60, "warning_days": 30, "critical_days": 14})
        stored = {
            x.key: x.value
            for x in db.exec(select(Setting))
            if x.key in {"info_days", "warning_days", "critical_days"}
        }
        for k, v in stored.items():
            try:
                thresholds[k] = int(v)
            except (ValueError, TypeError):
                pass

        services = {x.id: x for x in db.exec(select(Service))}
        results = list(db.exec(select(CertResult).where(CertResult.scan_id == latest.id)))
        count = 0

        for item in results:
            if not item.leaf_pem:
                continue
            srv = services.get(item.service_id)
            if not srv:
                continue

            raw = RawResult(
                reachable=True,
                leaf_pem=item.leaf_pem,
                subject_cn=item.subject_cn,
                san_dns=item.san_dns if isinstance(item.san_dns, list) else [],
                san_ip=item.san_ip if isinstance(item.san_ip, list) else [],
                issuer_cn=item.issuer_cn,
                not_before=item.not_before,
                not_after=item.not_after,
                key_type=item.key_type,
                key_size=item.key_size,
                sig_hash=item.sig_hash,
                chain_verify_code=item.chain_verify_code,
                chain_verify_message=item.chain_verify_message,
            )

            res = analyze(raw, srv, thresholds)
            item.days_left = res["days_left"]
            item.status = res["status"]
            item.risk_score = res["risk_score"]
            item.risk_level = res["risk_level"]
            item.findings = [f.__dict__ if hasattr(f, "__dict__") else f for f in res["findings"]]
            item.hostname_match = res.get("hostname_match")
            item.self_signed = res.get("self_signed")
            item.weak_crypto = res.get("weak_crypto")
            item.chain_status = chain_status(item.chain_verify_code, res.get("self_signed", False))

            db.add(item)
            count += 1

        db.commit()

    audit("RECOMPUTE", {"count": count})
    return count
