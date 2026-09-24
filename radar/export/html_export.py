from html import escape
def export_html(rows):
    body="".join(f"<tr><td>{escape(service.host)}</td><td>{escape(result.status)}</td><td>{result.days_left or ''}</td><td>{result.risk_score or ''}</td></tr>" for service,result in rows)
    return f"<!doctype html><meta charset='utf-8'><h1>Certificate Radar</h1><table><tr><th>Хост</th><th>Статус</th><th>Дни</th><th>Risk</th></tr>{body}</table>"
