from io import BytesIO
from openpyxl import Workbook
def export_xlsx(rows):
    wb=Workbook(); ws=wb.active; ws.append(["Сервис","Хост","Порт","Владелец","Статус","Дней до окончания","Risk Score"])
    for service,result in rows: ws.append([service.service_name or "",service.host,service.port,service.owner or "",result.status,result.days_left,result.risk_score])
    ws.auto_filter.ref=f"A1:G{ws.max_row}"
    ws.freeze_panes="A2"
    for column in ws.columns: ws.column_dimensions[column[0].column_letter].width=min(max(len(str(cell.value or "")) for cell in column)+2,40)
    data=BytesIO(); wb.save(data); return data.getvalue()
