from pathlib import Path
from radar.targets.parser import parse_file


def test_lab_targets_have_expected_import_report():
    path = Path(__file__).resolve().parents[1] / "lab" / "targets_lab.csv"
    report = parse_file(path.read_bytes(), path.name)
    assert len(report.services) == 10
    assert report.duplicates == 1
    assert len(report.invalid) == 1
