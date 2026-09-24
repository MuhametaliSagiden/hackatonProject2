import csv
import io
import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse


@dataclass
class ImportReport:
    services: list
    added: int = 0
    updated: int = 0
    duplicates: int = 0
    invalid: list = None

    def __post_init__(self):
        self.invalid = self.invalid or []


def _target(raw, max_hosts=256):
    value = raw.strip()
    if value.lower().startswith("https://"):
        parsed = urlparse(value)
        host, port = parsed.hostname, parsed.port or 443
    else:
        if "/" in value:
            net = ip_network(value, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > max_hosts:
                raise ValueError("CIDR содержит слишком много адресов")
            return [(str(x), 443) for x in hosts]
        host, port = value, 443
        if ":" in value and value.count(":") == 1:
            host, port_text = value.rsplit(":", 1)
            if port_text.isdigit():
                port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("порт должен быть от 1 до 65535")
    try:
        ip_address(host)
    except ValueError:
        host = host.rstrip(".").lower()
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split(".")
        ):
            raise ValueError("некорректное имя хоста")
    return [(host, port)]


def parse_text(text: str, filename="targets.txt", max_cidr_hosts=256):
    rows = []
    if filename.lower().endswith(".csv"):
        sample = text[:2048]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames or "target" not in reader.fieldnames:
            raise ValueError("CSV должен содержать колонку target")
        rows = [(i, r.get("target", ""), r) for i, r in enumerate(reader, 2)]
    else:
        rows = [
            (i, line.strip(), {})
            for i, line in enumerate(text.splitlines(), 1)
            if line.strip() and not line.lstrip().startswith("#")
        ]
    report = ImportReport([])
    seen = set()
    for line, raw, meta in rows:
        try:
            for host, port in _target(raw, max_cidr_hosts):
                key = (host, port)
                if key in seen:
                    report.duplicates += 1
                    continue
                seen.add(key)
                report.services.append(
                    {
                        "host": host,
                        "port": port,
                        "service_name": meta.get("service_name") or None,
                        "owner": meta.get("owner") or None,
                        "criticality": meta.get("criticality") or "medium",
                    }
                )
        except Exception as exc:
            report.invalid.append((line, raw, str(exc)))
    return report


def parse_file(data: bytes, filename: str, max_cidr_hosts=256):
    return parse_text(data.decode("utf-8-sig"), filename, max_cidr_hosts)
