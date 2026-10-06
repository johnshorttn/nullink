"""Direct Postfix adapter. Paused is deliberate and cannot be toggled by the web API.

Future activation requires network/DNS and a dedicated loopback submission service.
SMTP acceptance is never evidence of remote delivery. Ambiguous submission is not retried.
"""
import re, smtplib, ssl

class DirectPostfix:
    def __init__(self, enabled=False, host='mail.nullverse.cloud', port=2526):
        self.enabled, self.host, self.port = enabled, host, port
    def submit(self, sender, recipients, raw):
        if not self.enabled: return {'status':'paused','queue_id':None}
        with smtplib.SMTP('127.0.0.1',self.port,timeout=15) as smtp:
            smtp.ehlo()
            smtp._host=self.host
            smtp.starttls(context=ssl.create_default_context());smtp.ehlo()
            code,_=smtp.mail(sender)
            if code != 250: raise ValueError('Postfix rejected sender')
            for recipient in recipients:
                code,_=smtp.rcpt(recipient)
                if code not in (250,251):
                    smtp.rset();raise ValueError('Postfix rejected a recipient; no DATA submitted')
            code,response=smtp.data(raw)
            if code != 250: raise ValueError('Postfix did not accept message')
            match=re.search(rb'queued as ([A-F0-9]+)',response)
            return {'status':'accepted','queue_id':match.group(1).decode() if match else None}
