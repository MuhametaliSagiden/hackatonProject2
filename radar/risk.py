def score(status, findings, criticality="medium", days_left=None):
    points = {"Expired": 60, "Critical": 45, "Warning": 30, "Information": 10}.get(status, 0)
    if status == "Critical" and days_left is not None and days_left <= 7:
        points = 60
    points += sum(
        {"CHAIN_ERROR": 35, "SELF_SIGNED": 30, "HOSTNAME_MISMATCH": 35, "NO_OWNER": 10}.get(f.code, 0)
        for f in findings
    )
    if any(f.code in {"WEAK_KEY", "WEAK_SIGNATURE"} for f in findings):
        points += 15
    points += {"high": 20, "medium": 10, "low": 0}.get(criticality, 10)
    points = min(points, 100)
    return (
        points,
        "Critical" if points >= 80 else "High" if points >= 60 else "Medium" if points >= 30 else "Low",
    )
