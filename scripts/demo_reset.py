from datetime import UTC, datetime
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DATABASE = DATA / "radar.db"

def run(*args):
    subprocess.run([sys.executable, *args], cwd=ROOT, check=True)

def create_exports():
    from sqlmodel import select
    from radar.db import session
    from radar.export.csv_export import export_csv
    from radar.export.html_export import export_html
    from radar.export.xlsx_export import export_xlsx
    from radar.models import CertResult, Scan, Service

    db=session(); latest=db.exec(select(Scan).where(Scan.status == "done").order_by(Scan.id.desc())).first()
    results=list(db.exec(select(CertResult).where(CertResult.scan_id == latest.id))) if latest else []
    services={item.id:item for item in db.exec(select(Service))}; db.close()
    rows=[(services[item.service_id],item) for item in results]; output=ROOT/"demo"; output.mkdir(exist_ok=True)
    (output/"certificates.csv").write_text(export_csv(rows),encoding="utf-8")
    (output/"certificates.xlsx").write_bytes(export_xlsx(rows))
    (output/"certificates.html").write_text(export_html(rows),encoding="utf-8")

def main():
    DATA.mkdir(exist_ok=True)
    if DATABASE.exists():
        shutil.copy2(DATABASE,DATA/f"backup-{datetime.now(UTC):%Y%m%d-%H%M%S}.db")
        DATABASE.unlink()
    run("lab/make_certs.py"); run("-m","radar.cli","init-db")
    targets=ROOT/"lab"/"targets_lab.csv"
    if targets.exists(): run("-m","radar.cli","import",str(targets))
    if "--seed" in sys.argv:
        run("-m","radar.cli","scan"); shutil.copy2(DATABASE,DATA/"radar_demo_seed.db"); create_exports()

if __name__ == "__main__": main()
