import argparse
import sys
from pathlib import Path

from sqlmodel import select

from .db import init_db, session
from .models import CertResult, Service
from .services import import_targets, recompute_latest, run_scan


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_line = "| " + " | ".join(h.ljust(w) for h, w in zip(headers, col_widths, strict=False)) + " |"

    lines = [sep, header_line, sep]
    for row in rows:
        r_str = "| " + " | ".join(str(val).ljust(w) for val, w in zip(row, col_widths, strict=False)) + " |"
        lines.append(r_str)
    lines.append(sep)
    return "\n".join(lines)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="radar", description="Certificate Radar CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Инициализировать базу данных SQLite")

    p_import = sub.add_parser("import", help="Импортировать цели из файла")
    p_import.add_argument("file", help="Путь к файлу целей (CSV или TXT)")

    sub.add_parser("scan", help="Запустить сканирование всех целей")

    sub.add_parser("recompute", help="Пересчитать результаты последнего скана с текущими настройками")

    p_serve = sub.add_parser("serve", help="Запустить веб-сервер")
    p_serve.add_argument("--host", default="127.0.0.1", help="Хост сервера")
    p_serve.add_argument("--port", type=int, default=8000, help="Порт сервера")

    args = parser.parse_args()

    if args.command == "init-db":
        init_db()
        print("База данных создана и обновлена.")

    elif args.command == "import":
        content = Path(args.file).read_bytes()
        rep = import_targets(content, args.file)
        print(
            f"Добавлено: {rep.added}; Обновлено: {rep.updated}; Дубликаты: {rep.duplicates}; Ошибки: {len(rep.invalid)}"
        )
        if rep.invalid:
            print("\nОшибочные строки:")
            for line_no, raw_text, reason in rep.invalid:
                print(f"  [Строка {line_no}] '{raw_text}': {reason}")

    elif args.command == "scan":
        scan = run_scan(triggered_by="cli")
        with session() as db:
            results = list(db.exec(select(CertResult).where(CertResult.scan_id == scan.id)))
            services = {s.id: s for s in db.exec(select(Service))}

        headers = ["Хост", "Статус", "Дни", "Риск", "Находки"]
        rows = []
        for r in results:
            srv = services.get(r.service_id)
            host_str = f"{srv.host}:{srv.port}" if srv else "unknown"
            days_str = str(r.days_left) if r.days_left is not None else "—"
            risk_str = f"{r.risk_score} {r.risk_level}" if r.risk_score is not None else "N/A"
            findings = r.findings if isinstance(r.findings, list) else []
            codes = [f.get("code", "") for f in findings if isinstance(f, dict)]
            findings_str = ", ".join(codes) if codes else "—"
            rows.append([host_str, r.status, days_str, risk_str, findings_str])

        print(format_table(headers, rows))
        print(f"\nСкан #{scan.id} завершён: {scan.processed}/{scan.total} обработано. Статус: {scan.status}")

    elif args.command == "recompute":
        count = recompute_latest()
        print(f"Пересчитано результатов последнего скана: {count}")

    elif args.command == "serve":
        import uvicorn

        uvicorn.run("radar.web.app:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
