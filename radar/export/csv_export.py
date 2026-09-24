import csv, io
def export_csv(rows):
    output=io.StringIO(); writer=csv.writer(output, lineterminator="\n"); writer.writerow(["Сервис","Хост","Порт","Владелец","Статус","Дней до окончания","Risk Score"])
    for service,result in rows: writer.writerow([service.service_name or "",service.host,service.port,service.owner or "",result.status,result.days_left if result.days_left is not None else "",result.risk_score if result.risk_score is not None else ""])
    return "\ufeff"+output.getvalue()
