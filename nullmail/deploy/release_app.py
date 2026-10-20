#!/usr/bin/env python3
"""Root-only app deployment with private checkpoint and guarded app-only rollback.

Never alters/restarts Postfix, submission, controller, DNS, Caddy or auth services.
Run only after fixture tests pass. Requires the inspection backup pointer.
"""
import datetime, hashlib, json, os, pathlib, shutil, sqlite3, subprocess, time, urllib.request

SOURCE=pathlib.Path(__file__).resolve().parents[1]
RUNTIME=pathlib.Path('/usr/local/lib/nullmail')
BACKUPS=pathlib.Path('/root/nullmail-build-backup')
FILES=['app.py','core.py','api_v1.py','workspace.py','rules.py','cases.py','gmail.py','openapi.json','static/app.js','static/workspace.js','static/cases.js','static/index.html','static/style.css']

def hashes(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}

def health():
    for _ in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8789/health',timeout=2) as response:
                if response.status==200 and json.load(response).get('ok'):return
        except (OSError,ValueError):pass
        time.sleep(1)
    raise RuntimeError('Nullmail loopback health check failed')

def main():
    if os.geteuid()!=0:raise RuntimeError('Run as root')
    os.umask(0o077)
    baseline=pathlib.Path((BACKUPS/'gmail-latest').read_text().strip())
    # Reject concurrent runtime changes instead of overwriting them.
    if hashes(RUNTIME)!=hashes(baseline/'runtime'):raise RuntimeError('Runtime changed since inspection; review concurrent changes first')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    checkpoint=BACKUPS/('gmail-deploy-'+stamp);checkpoint.mkdir(mode=0o700)
    stage=pathlib.Path('/usr/local/lib/nullmail-stage-'+stamp)
    previous=pathlib.Path('/usr/local/lib/nullmail-before-'+stamp)
    shutil.copytree(RUNTIME,stage)
    for relative in FILES:shutil.copy2(SOURCE/relative,stage/relative)
    for p in [stage,*stage.rglob('*')]:
        if p.is_symlink():raise RuntimeError('Unexpected runtime symlink')
        os.chown(p,0,0);os.chmod(p,0o755 if p.is_dir() else 0o644)
    staged_hashes=hashes(stage)
    subprocess.run(['systemctl','stop','nullmail'],check=True)
    installed=False
    try:
        shutil.copytree(RUNTIME,checkpoint/'runtime')
        shutil.copytree(SOURCE,checkpoint/'source',ignore=shutil.ignore_patterns('__pycache__','*.bak*'))
        shutil.copytree('/var/lib/nullmail/john/Maildir',checkpoint/'Maildir',symlinks=True)
        cache=pathlib.Path('/var/lib/nullmail/app/gmail-cache')
        if cache.exists():shutil.copytree(cache,checkpoint/'gmail-cache',symlinks=True)
        for p in pathlib.Path('/var/lib/nullmail/app').glob('*.sqlite3'):
            with sqlite3.connect(p) as src,sqlite3.connect(checkpoint/p.name) as dst:
                src.backup(dst)
                if dst.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise RuntimeError('Database backup integrity check failed')
        if hashes(RUNTIME)!=hashes(baseline/'runtime'):raise RuntimeError('Concurrent runtime edit detected before installation')
        RUNTIME.rename(previous);stage.rename(RUNTIME);installed=True
        subprocess.run(['systemctl','start','nullmail'],check=True);health()
        for host in ['nullmail.nullverse.cloud','nullmail.216.158.238.236.sslip.io']:
            with urllib.request.urlopen('https://'+host+'/health',timeout=30) as response:
                if response.status!=200 or not json.load(response).get('ok'):raise RuntimeError('Public health check failed')
        subprocess.run(['runuser','-u','morc','--','python3',str(SOURCE/'tests/release_health.py')],check=True)
        record={'checkpoint':str(checkpoint),'previous_runtime':str(previous),'deployed_runtime':str(RUNTIME),'deployed_hashes':staged_hashes,'health':'passed','timestamp':stamp}
        (checkpoint/'release.json').write_text(json.dumps(record,indent=2)+'\n')
        (BACKUPS/'gmail-deploy-latest').write_text(str(checkpoint))
        print(json.dumps({'checkpoint':str(checkpoint),'previous_runtime':str(previous),'health':'loopback and both public hosts passed'}))
    except Exception:
        if installed:
            if hashes(RUNTIME)!=staged_hashes:raise RuntimeError('Health failed with concurrent runtime changes; refusing blind rollback')
            subprocess.run(['systemctl','stop','nullmail'],check=True)
            failed=pathlib.Path(str(stage)+'-failed');RUNTIME.rename(failed);previous.rename(RUNTIME)
        subprocess.run(['systemctl','start','nullmail'],check=True)
        raise

if __name__=='__main__':main()
