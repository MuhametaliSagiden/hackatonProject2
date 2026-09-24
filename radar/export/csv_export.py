import csv
import io
from typing import Any

COLUMNS = [
    "Сервис",
    "Хост",
    "Порт",
    "Владелец",
    "Критичность",
    "CN",
    "SAN",
    "Issuer",
    "Thumbprint (SHA-1)",
    "Thumbprint (SHA-256)",
    "Действует с",
    "Действует до",
    "Дней осталось",
    "Статус",
    "Цепочка",
    "Имя совпадает",
    "Self-signed",
    "Ключ",
    "Подпись",
    "TLS версия",
    "Ошибка",
    "Risk Score",
    "Уровень риска",
    "Проблемы",
    "Рекомендации",
]


def extract_row_values(service: Any, result: Any) -> list[str]:
    san_list = getattr(result, "san_dns", []) if isinstance(getattr(result, "san_dns", []), list) else []
    san_ip = getattr(result, "san_ip", []) if isinstance(getattr(result, "san_ip", []), list) else []
    all_sans = san_list + san_ip

    not_before_str = result.not_before.strftime("%d.%m.%Y") if getattr(result, "not_before", None) else ""
    not_after_str = result.not_after.strftime("%d.%m.%Y") if getattr(result, "not_after", None) else ""

    findings = result.findings if isinstance(getattr(result, "findings", None), list) else []
    reasons = [f.get("reason", f.get("code", "")) for f in findings if isinstance(f, dict)]
    recommendations = [
        f.get("recommendation", "") for f in findings if isinstance(f, dict) and f.get("recommendation")
    ]

    hn_match = getattr(result, "hostname_match", None)
    hn_match_str = "Да" if hn_match is True else ("Нет" if hn_match is False else "")

    self_signed = getattr(result, "self_signed", None)
    self_signed_str = "Да" if self_signed is True else ("Нет" if self_signed is False else "")

    key_type = getattr(result, "key_type", None) or ""
    key_size = getattr(result, "key_size", None)
    key_str = f"{key_type} {key_size}".strip() if (key_type or key_size) else ""

    return [
        getattr(service, "service_name", None) or "",
        str(getattr(service, "host", "")),
        str(getattr(service, "port", 443)),
        getattr(service, "owner", None) or "",
        getattr(service, "criticality", "medium"),
        getattr(result, "subject_cn", None) or "",
        ", ".join(str(s) for s in all_sans),
        getattr(result, "issuer_cn", None) or getattr(result, "issuer_full", None) or "",
        getattr(result, "thumbprint_sha1", None) or "",
        getattr(result, "thumbprint_sha256", None) or "",
        not_before_str,
        not_after_str,
        str(result.days_left) if getattr(result, "days_left", None) is not None else "",
        getattr(result, "status", ""),
        getattr(result, "chain_status", ""),
        hn_match_str,
        self_signed_str,
        key_str,
        getattr(result, "sig_hash", None) or "",
        getattr(result, "tls_version", None) or "",
        getattr(result, "error", None) or "",
        str(result.risk_score) if getattr(result, "risk_score", None) is not None else "",
        getattr(result, "risk_level", ""),
        "; ".join(reasons),
        "; ".join(recommendations),
    ]


def export_csv(rows: list[tuple[Any, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", lineterminator="\n")
    writer.writerow(COLUMNS)
    for service, result in rows:
        writer.writerow(extract_row_values(service, result))
    return "\ufeff" + output.getvalue()
