"""Certificate-authenticated local submission. Acceptance is not delivery."""
import json, re, smtplib, ssl
from pathlib import Path

CONFIG = Path('/etc/nullmail/outbound.json')

def outbound_enabled():
    try:
        return json.loads(CONFIG.read_text()).get('enabled') is True
    except FileNotFoundError:
        return False

class DirectPostfix:
    def __init__(self, enabled=False, host='mail.nullverse.cloud', port=2526):
        self.enabled, self.host, self.port = enabled, host, port
    def submit(self, sender, recipients, raw, envid=None):
        """envid: request DSN (NOTIFY=SUCCESS,FAILURE,DELAY; RET=HDRS) when the server advertises DSN."""
        if not self.enabled: return {'status':'paused','queue_id':None}
        smtp = None
        data_started = False
        try:
            context = ssl.create_default_context()
            context.load_cert_chain('/etc/nullmail/submission.crt','/etc/nullmail/submission.key')
            smtp = smtplib.SMTP('127.0.0.1',self.port,timeout=15)
            smtp.ehlo(); smtp._host = self.host
            smtp.starttls(context=context); smtp.ehlo()
            dsn = bool(envid) and smtp.has_extn('dsn')
            code,_ = smtp.mail(sender, ['RET=HDRS','ENVID='+envid] if dsn else [])
            if code != 250: return {'status':'rejected','queue_id':None}
            for recipient in recipients:
                code,_ = smtp.rcpt(recipient, ['NOTIFY=SUCCESS,FAILURE,DELAY','ORCPT=rfc822;'+recipient] if dsn else [])
                if code not in (250,251):
                    smtp.rset(); return {'status':'rejected','queue_id':None}
            data_started = True
            code,response = smtp.data(raw)
            if code != 250: return {'status':'rejected','queue_id':None}
            match = re.search(rb'queued as ([A-F0-9]+)',response)
            return {'status':'accepted','queue_id':match.group(1).decode() if match else None,'dsn':dsn}
        except smtplib.SMTPDataError:
            return {'status':'rejected','queue_id':None}
        except Exception:
            return {'status':'unknown' if data_started else 'rejected','queue_id':None}
        finally:
            # A failed QUIT after a 250 must not turn acceptance into a retry.
            if smtp is not None: smtp.close()
