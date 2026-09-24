from datetime import datetime
from pathlib import Path
import shutil, subprocess, sys

root=Path(__file__).resolve().parent.parent; data=root/"data"; data.mkdir(exist_ok=True); db=data/"radar.db"
if db.exists(): shutil.copy2(db, data/f"backup-{datetime.now():%Y%m%d-%H%M%S}.db"); db.unlink()
subprocess.run([sys.executable, "-m", "radar.cli", "init-db"], cwd=root, check=True)
targets=root/"lab"/"targets_lab.csv"
if targets.exists(): subprocess.run([sys.executable, "-m", "radar.cli", "import", str(targets)], cwd=root, check=True)
if "--seed" in sys.argv: subprocess.run([sys.executable, "-m", "radar.cli", "scan"], cwd=root, check=True)
