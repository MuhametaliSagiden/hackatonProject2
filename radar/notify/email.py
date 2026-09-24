from email.message import EmailMessage
import smtplib
class EmailChannel:
    def __init__(self, host, port, sender, recipients): self.host,self.port,self.sender,self.recipients=host,port,sender,recipients
    def send(self, message):
        email=EmailMessage(); email["Subject"]="Certificate Radar"; email["From"]=self.sender; email["To"]=", ".join(self.recipients); email.set_content(message)
        smtp=smtplib.SMTP_SSL(self.host,self.port,timeout=10) if self.port == 465 else smtplib.SMTP(self.host,self.port,timeout=10)
        with smtp: smtp.send_message(email)
        return True
