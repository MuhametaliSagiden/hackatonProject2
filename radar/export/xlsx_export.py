from io import BytesIO
from openpyxl import Workbook
def export_xlsx(rows):
    wb=Workbook(); ws=wb.active; ws.append(["Сервис","Хост","Порт","Владелец","Статус","Дней до окончания","Risk Score"])
    for service,result in rows: ws.append([service.service_name or "",service.host,service.port,service.owner or "",result.status,result.days_left,result.risk_score])
    data=BytesIO(); wb.save(data); return data.getvalue()
