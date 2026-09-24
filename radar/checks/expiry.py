def status_for_days(days, thresholds):
    if days < 0: return "Expired"
    if days <= thresholds["critical_days"]: return "Critical"
    if days <= thresholds["warning_days"]: return "Warning"
    if days <= thresholds["info_days"]: return "Information"
    return "OK"
