from datetime import UTC, datetime
from html import escape
from typing import Any

from .csv_export import COLUMNS, extract_row_values

STATUS_COLORS = {
    "OK": "#28a745",
    "Information": "#17a2b8",
    "Warning": "#ffc107",
    "Critical": "#fd7e14",
    "Expired": "#dc3545",
    "Unreachable": "#6c757d",
}


def export_html(rows: list[tuple[Any, Any]]) -> str:
    now_str = datetime.now(UTC).strftime("%d.%m.%Y %H:%M UTC")

    # Status summary
    summary_counts: dict[str, int] = {
        "OK": 0,
        "Information": 0,
        "Warning": 0,
        "Critical": 0,
        "Expired": 0,
        "Unreachable": 0,
    }
    for _, result in rows:
        st = getattr(result, "status", "")
        if st in summary_counts:
            summary_counts[st] += 1
        else:
            summary_counts[st] = summary_counts.get(st, 0) + 1

    summary_items_html = "".join(
        f'<div class="summary-card" style="border-left: 4px solid {STATUS_COLORS.get(st, "#ccc")}">'
        f'<span class="summary-title">{escape(st)}</span>'
        f'<span class="summary-count">{count}</span>'
        f"</div>"
        for st, count in summary_counts.items()
    )

    # Table headers
    headers_html = "".join(f"<th>{escape(col)}</th>" for col in COLUMNS)

    # Table rows
    rows_html = []
    for service, result in rows:
        values = extract_row_values(service, result)
        st = getattr(result, "status", "")
        st_color = STATUS_COLORS.get(st, "#000")
        cells_html = []
        for i, val in enumerate(values):
            escaped = escape(str(val))
            if COLUMNS[i] == "Статус":
                cells_html.append(f'<td><strong style="color: {st_color}">{escaped}</strong></td>')
            else:
                cells_html.append(f"<td>{escaped}</td>")
        rows_html.append(f"<tr>{''.join(cells_html)}</tr>")

    table_body = "".join(rows_html)

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Certificate Radar — Экспорт</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 20px;
      color: #333;
      background: #f8f9fa;
    }}
    h1 {{
      margin-bottom: 5px;
      color: #1a253c;
    }}
    .meta {{
      color: #666;
      margin-bottom: 20px;
      font-size: 0.9rem;
    }}
    .summary-grid {{
      display: flex;
      gap: 15px;
      margin-bottom: 25px;
      flex-wrap: wrap;
    }}
    .summary-card {{
      background: #fff;
      padding: 10px 20px;
      border-radius: 6px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      display: flex;
      flex-direction: column;
      min-width: 110px;
    }}
    .summary-title {{
      font-size: 0.85rem;
      color: #777;
    }}
    .summary-count {{
      font-size: 1.5rem;
      font-weight: bold;
      color: #222;
    }}
    .table-container {{
      overflow-x: auto;
      background: #fff;
      border-radius: 6px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      white-space: nowrap;
    }}
    th {{
      background: #1a253c;
      color: #fff;
      text-align: left;
      padding: 10px 12px;
      font-weight: 600;
    }}
    td {{
      padding: 8px 12px;
      border-bottom: 1px solid #e9ecef;
    }}
    tr:hover td {{
      background: #f1f3f5;
    }}
  </style>
</head>
<body>
  <h1>Certificate Radar — Отчёт по сертификатам</h1>
  <div class="meta">Дата формирования: {now_str} | Всего объектов: {len(rows)}</div>
  
  <div class="summary-grid">
    {summary_items_html}
  </div>

  <div class="table-container">
    <table>
      <thead>
        <tr>{headers_html}</tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>
  </div>
</body>
</html>"""
