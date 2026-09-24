import argparse

from .db import init_db
from .services import import_targets, run_scan


def main():
    parser=argparse.ArgumentParser(prog="radar"); sub=parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db"); p=sub.add_parser("import"); p.add_argument("file"); sub.add_parser("scan"); p=sub.add_parser("serve"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8000)
    args=parser.parse_args()
    if args.command == "init-db": init_db(); print("База данных создана")
    elif args.command == "import":
        with open(args.file,"rb") as f: r=import_targets(f.read(), args.file); print(f"Добавлено: {r.added}; Обновлено: {r.updated}; Дубликаты: {r.duplicates}; Ошибки: {len(r.invalid)}")
    elif args.command == "scan":
        s=run_scan(); print(f"Скан завершён: {s.processed}/{s.total}")
    else:
        import uvicorn; uvicorn.run("radar.web.app:app", host=args.host, port=args.port)
