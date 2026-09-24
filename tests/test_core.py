from radar.risk import score
from radar.targets.parser import parse_text


def test_parser_deduplicates_and_urls():
    report = parse_text("https://A.example:8443/x\na.example:8443\n")
    assert report.duplicates == 1
    assert report.services[0]["host"] == "a.example"


def test_risk_levels():
    assert score("Critical", [], "high")[1] == "High"
    assert score("Expired", [], "high")[0] == 80
    assert score("Critical", [], "high", days_left=5) == (80, "Critical")
