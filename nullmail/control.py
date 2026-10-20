"""Root-owned, fixed-schema Unix-socket Postfix map controller.

No shell, caller paths, arbitrary configuration, queue release or DNS writes.
"""
import grp, json, os, re, shutil, socketserver, subprocess, tempfile, threading, time
from pathlib import Path
from core import ALIASES
SOCKET = '/run/nullmail-control/control.sock'
ROOT = Path('/etc/postfix')
DOMAINS = ROOT / 'nullmail_project_domains'
MAP = ROOT / 'nullmail_project_aliases'
LOCK = threading.Lock()
CACHE = {}

def run(*args):
    return subprocess.check_output(args, timeout=12, stderr=subprocess.DEVNULL, text=True).strip()

def labels():
    if not DOMAINS.exists(): return []
    return sorted(line.split()[0].removesuffix('.nullverse.cloud') for line in DOMAINS.read_text().splitlines() if line.strip())

def validate_label(label):
    if not isinstance(label, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,30}[a-z0-9]|[a-z]', label):
        raise ValueError('Use 1–32 lowercase letters, digits or internal hyphens')
    if label in {'www','mail','nullmail','smtp','imap','pop','autodiscover','_dmarc'}:
        raise ValueError('Reserved hostname')
    return label

def update(label):
    validate_label(label)
    with LOCK:
        names = set(labels()); names.add(label)
        if len(names) > 100: raise ValueError('Project limit reached')
        domain_text = ''.join(f'{n}.nullverse.cloud OK\n' for n in sorted(names))
        alias_text = ''.join(f'{a}@{n}.nullverse.cloud john@nullverse.cloud\n' for n in sorted(names) for a in ALIASES)
        # Single threaded root controller; keep existing configuration on every failure.
        paths = [DOMAINS, Path(str(DOMAINS)+'.db'), MAP, Path(str(MAP)+'.db')]
        previous = {p: p.read_bytes() if p.exists() else None for p in paths}
        try:
            for dest, content in [(MAP,alias_text),(DOMAINS,domain_text)]:
                fd, temp = tempfile.mkstemp(prefix='.nullmail-', dir=ROOT)
                try:
                    with os.fdopen(fd,'w') as f: f.write(content); f.flush(); os.fsync(f.fileno())
                    os.chmod(temp,0o644); run('/usr/sbin/postmap', 'hash:'+temp)
                    os.chmod(temp+'.db',0o644)
                    os.replace(temp+'.db',str(dest)+'.db'); os.replace(temp,dest)
                finally:
                    for p in (temp,temp+'.db'):
                        if os.path.exists(p): os.unlink(p)
            run('/usr/sbin/postfix','check')
            run('/usr/sbin/postfix','reload')
        except Exception:
            for p, content in previous.items():
                if content is None: p.unlink(missing_ok=True)
                else: p.write_bytes(content); p.chmod(0o644)
            raise
        CACHE.clear()
    return {'registered': label, 'dns': 'pending verification'}

def dig(name, kind):
    try: return run('/usr/bin/dig','+time=2','+tries=1','+short',name,kind).splitlines()
    except (subprocess.SubprocessError,OSError): return []

def snapshot():
    if CACHE.get('expires',0) > time.time(): return CACHE['value']
    projects=[]
    for label in [''] + labels():
        domain = label+'.nullverse.cloud' if label else 'nullverse.cloud'
        mx = dig(domain,'MX')
        good = bool(mx) and all(re.fullmatch(r'\d+ mail\.nullverse\.cloud\.', x) for x in mx)
        projects.append({'name':label or 'nullverse','domain':domain,'dns_status':'verified' if good else 'pending',
                         'mx_observed':mx,'mx_required':f'{domain}. MX 25 mail.nullverse.cloud.',
                         'aliases': ([f'john@{domain}'] if not label else []) + [f'{a}@{domain}' for a in ALIASES]})
    disk = shutil.disk_usage('/var/lib/nullmail')
    queues=[]
    for line in run('/usr/sbin/postqueue','-j').splitlines():
        item=json.loads(line);queues.append({'id':item['queue_id'],'queue':item['queue_name']})
    value={'projects':projects,'outbound':{'paused':True,'transport':'Direct Postfix / destination MX',
           'reason':'Nullmail sending is paused independently of Postfix. Earlier TCP 25 probes timed out; the owner is investigating connectivity. This app performs no outbound probes. Send stores a paused Outbox item without transmitting or automatic retry.',
           'defer_transports':run('/usr/sbin/postconf','-h','defer_transports'),
           'header_checks':run('/usr/sbin/postconf','-h','header_checks'), 'queued':queues},
           'inbound':{'address':'john@nullverse.cloud','verified_external':True,'catchall':False,'max_message_bytes':int(run('/usr/sbin/postconf','-h','message_size_limit'))},
           'capacity':{'total':disk.total,'free':disk.free},
           'dns':{'mail_a':dig('mail.nullverse.cloud','A'),'ptr':dig('236.238.158.216.in-addr.arpa','PTR'),
                  'spf':[x for x in dig('nullverse.cloud','TXT') if 'v=spf1' in x],
                  'dmarc':dig('_dmarc.nullverse.cloud','TXT'),
                  'dkim':'No signer or selector was provisioned by Nullmail. Current Postfix milter settings: '+(run('/usr/sbin/postconf','-h','smtpd_milters') or '(none)')+' / '+(run('/usr/sbin/postconf','-h','non_smtpd_milters') or '(none)')+'. DNS selectors cannot be enumerated; verify any separately configured signer with its administrator.',
                  'ptr_required':'mail.nullverse.cloud (change at VPS provider)',
                  'spf_guidance':'Confirm every legitimate sender before choosing an SPF policy; no record is automatically published.',
                  'dmarc_guidance':'Publish a deliberate policy after SPF/DKIM alignment. No DNS records are written by this app.'},
           'checked_at':time.time()}
    CACHE.update(value=value,expires=time.time()+60)
    return value

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            raw=self.rfile.readline(2049)
            if len(raw)>2048: raise ValueError('Request too large')
            data=json.loads(raw)
            if data == {'op':'status'}: result=snapshot()
            elif isinstance(data,dict) and set(data)=={'op','label'} and data['op']=='register': result=update(data['label'])
            else: raise ValueError('Unknown operation')
            response={'ok':True,'result':result}
        except ValueError as e: response={'ok':False,'error':str(e)}
        except Exception: response={'ok':False,'error':'Controller operation failed; inspect administrator service logs'}
        self.wfile.write(json.dumps(response).encode()+b'\n')

if __name__=='__main__':
    Path(SOCKET).unlink(missing_ok=True)
    with socketserver.UnixStreamServer(SOCKET,Handler) as server:
        os.chown(SOCKET,0,grp.getgrnam('nullmail').gr_gid);os.chmod(SOCKET,0o660)
        server.serve_forever()
