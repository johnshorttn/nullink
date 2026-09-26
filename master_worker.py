#!/usr/bin/env python3
"""Private, single-runner Codex job service. Standard library only, Linux."""
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import socketserver
import sqlite3
import subprocess
import threading
import time
import uuid

MAX_REQUEST = 262144
TERMINAL = {'succeeded', 'failed', 'cancelled', 'timed_out', 'interrupted'}


class Worker:
    def __init__(self, config):
        self.config = config
        self.state = Path(config['state_dir'])
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lockfile = open(self.state / 'worker.lock', 'a')
        try:
            fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lockfile.close()
            raise
        self.db = sqlite3.connect(self.state / 'jobs.sqlite3', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, project TEXT, prompt TEXT, parent TEXT,
            state TEXT, created REAL, updated REAL, session TEXT,
            output TEXT DEFAULT '', exit_code INTEGER, request_key TEXT UNIQUE);
          CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, at REAL, action TEXT, job TEXT);
        ''')
        self.db.execute("UPDATE jobs SET state='interrupted', updated=? WHERE state IN ('running','cancelling')", (time.time(),))
        self.db.commit()

    def close(self):
        self.db.close()
        self.lockfile.close()

    def project(self, name):
        if name not in self.config['projects']:
            raise ValueError('Unknown project')
        path = Path(self.config['projects'][name]).resolve(strict=True)
        if not path.is_dir():
            raise ValueError('Project is not a directory')
        return str(path)

    def audit(self, action, job=''):
        self.db.execute('INSERT INTO audit(at,action,job) VALUES(?,?,?)', (time.time(), action, job))

    def get(self, job_id):
        row = self.db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown job')
        return dict(row)

    @staticmethod
    def public(row):
        return {k: v for k, v in row.items() if k not in ('prompt', 'request_key')}

    def submit(self, args, parent=None):
        prompt = args.get('prompt')
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 24000:
            raise ValueError('prompt must contain 1-24000 characters')
        project = args.get('project')
        session = None
        if parent:
            old = self.get(parent)
            if old['state'] not in TERMINAL or not old['session']:
                raise ValueError('Reply requires a finished job with a Codex session')
            project, session = old['project'], old['session']
        self.project(project)
        key = args.get('request_key')
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError('request_key is required (1-128 characters)')
        existing = self.db.execute('SELECT * FROM jobs WHERE request_key=?', (key,)).fetchone()
        if existing:
            if (existing['prompt'], existing['project'], existing['parent']) != (prompt, project, parent):
                raise ValueError('request_key already used for a different task')
            return self.public(dict(existing))
        if self.db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running','cancelling')").fetchone()[0] >= 20:
            raise ValueError('Job queue is full')
        job = uuid.uuid4().hex
        now = time.time()
        self.db.execute('INSERT INTO jobs(id,project,prompt,parent,state,created,updated,session,request_key) VALUES(?,?,?,?,?,?,?,?,?)',
                        (job, project, prompt, parent, 'queued', now, now, session, key))
        self.audit('submit', job)
        self.db.commit()
        return self.public(self.get(job))

    def call(self, name, args):
        if not isinstance(args, dict):
            raise ValueError('arguments must be an object')
        with self.lock:
            if name == 'master_capabilities':
                return {'version': '1.0', 'projects': list(self.config['projects']),
                        'services': self.config.get('services', []),
                        'sandbox': self.config.get('sandbox', 'workspace-write'),
                        'timeout_seconds': self.config.get('timeout_seconds', 1800),
                        'concurrency': 1, 'reply_mode': 'resume finished session',
                        'uid': os.getuid()}
            if name == 'agent_start_task':
                return self.submit(args)
            if name == 'agent_reply':
                return self.submit(args, args['job_id'])
            if name == 'agent_task_status':
                return self.public(self.get(args['job_id']))
            if name == 'agent_list_tasks':
                return [self.public(dict(r)) for r in self.db.execute('SELECT * FROM jobs ORDER BY created DESC LIMIT 50')]
            if name == 'agent_cancel_task':
                job = self.get(args['job_id'])
                state = 'cancelled' if job['state'] == 'queued' else 'cancelling'
                if job['state'] not in TERMINAL:
                    self.db.execute('UPDATE jobs SET state=?, updated=? WHERE id=?', (state, time.time(), job['id']))
                    self.audit('cancel', job['id'])
                    self.db.commit()
                return self.public(self.get(job['id']))
            if name == 'master_audit':
                return [dict(r) for r in self.db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
        if name == 'repo_status':
            cwd = self.project(args['project'])
            return self.command(['git', '-c', 'core.fsmonitor=false', '-C', cwd, 'status', '--porcelain=v1', '--branch'])
        if name == 'service_status':
            service = args.get('service')
            if service not in self.config.get('services', []):
                raise ValueError('Unknown service')
            return self.command(['systemctl', 'show', service, '--property=Id,ActiveState,SubState,MainPID,Result'])
        if name == 'server_status':
            import shutil
            disk = shutil.disk_usage(self.state)
            return {'hostname': os.uname().nodename, 'load': os.getloadavg(),
                    'disk_free_bytes': disk.free, 'disk_total_bytes': disk.total,
                    'codex_executable_exists': Path(self.config['codex_bin']).is_file()}
        raise ValueError('Unknown tool')

    @staticmethod
    def command(argv):
        # Fixed diagnostics only. No shell, user flags, hooks, or arbitrary paths.
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              start_new_session=True, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'}) as proc:
            output = bytearray()
            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 10
            while sel.get_map():
                if time.monotonic() > deadline or len(output) >= 32768:
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    break
                for key, _ in sel.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk: sel.unregister(key.fileobj)
                    else: output.extend(chunk)
            sel.close()
            proc.wait()
            return {'exit_code': proc.returncode, 'output': bytes(output[:32768]).decode(errors='replace')}

    def argv(self, job):
        argv = [self.config['codex_bin'], '--sandbox', self.config.get('sandbox', 'workspace-write'),
                '--ask-for-approval', 'never', 'exec']
        if job['parent']:
            argv += ['resume', '--json', job['session'], '-']
        else:
            argv += ['--json', '-']
        return argv

    def update(self, job, **fields):
        with self.lock:
            fields['updated'] = time.time()
            self.db.execute('UPDATE jobs SET ' + ','.join(k+'=?' for k in fields) + ' WHERE id=?', (*fields.values(), job))
            self.db.commit()

    def run_one(self):
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created LIMIT 1").fetchone()
            if row is None: return False
            job = dict(row)
            self.update(job['id'], state='running')
            self.audit('start', job['id'])
            self.db.commit()
        proc = None
        output = ''
        pending = b''
        total = 0
        state = 'failed'
        sel = selectors.DefaultSelector()
        try:
            env = {k: v for k, v in os.environ.items() if not k.startswith(('NULLINK_', 'MASTER_'))}
            proc = subprocess.Popen(self.argv(job), cwd=self.project(job['project']), env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  start_new_session=True)
            os.set_blocking(proc.stdin.fileno(), False)
            prompt = memoryview(job['prompt'].encode())
            sel.register(proc.stdin, selectors.EVENT_WRITE)
            sel.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + self.config.get('timeout_seconds', 1800)
            while sel.get_map():
                with self.lock: cancelled = self.get(job['id'])['state'] == 'cancelling'
                if cancelled or self.stop.is_set() or time.monotonic() >= deadline:
                    state = 'cancelled' if cancelled else ('interrupted' if self.stop.is_set() else 'timed_out')
                    break
                for key, _ in sel.select(0.1):
                    if key.fileobj is proc.stdin:
                        try: prompt = prompt[os.write(proc.stdin.fileno(), prompt):]
                        except BrokenPipeError: prompt = memoryview(b'')
                        if not prompt:
                            sel.unregister(proc.stdin)
                            proc.stdin.close()
                        continue
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        sel.unregister(proc.stdout)
                        continue
                    total += len(chunk)
                    if total > self.config.get('max_output_bytes', 2097152):
                        raise ValueError('Job output limit exceeded')
                    pending += chunk
                    for line in pending.split(b'\n')[:-1]:
                        try:
                            event = json.loads(line)
                            if event.get('type') == 'thread.started':
                                session = event.get('thread_id', '')
                                # Reject flags or arbitrary values before passing a saved ID to CLI.
                                uuid.UUID(session)
                                self.update(job['id'], session=session)
                        except (ValueError, AttributeError, TypeError): pass
                    pending = pending.split(b'\n')[-1]
                    if len(pending) > 65536: pending = b''
                    output = (output + chunk.decode(errors='replace'))[-32768:]
                    self.update(job['id'], output=output)
            else:
                # EOF can precede process exit. Keep cancellation/timeout responsive.
                while proc.poll() is None and time.monotonic() < deadline and not self.stop.is_set():
                    with self.lock: cancelled = self.get(job['id'])['state'] == 'cancelling'
                    if cancelled: break
                    self.stop.wait(0.1)
                if cancelled: state = 'cancelled'
                elif self.stop.is_set(): state = 'interrupted'
                elif proc.poll() is None: state = 'timed_out'
                else: state = 'succeeded' if proc.returncode == 0 else 'failed'
            # Kill remaining descendants, including on normal parent exit.
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
        except Exception as exc:
            if proc:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait()
            output = (output + '\n' + type(exc).__name__ + ': ' + str(exc))[-32768:]
        finally:
            if proc:
                for stream in (proc.stdin, proc.stdout):
                    if stream and not stream.closed: stream.close()
            sel.close()
        with self.lock:
            if self.get(job['id'])['state'] == 'cancelling': state = 'cancelled'
            self.update(job['id'], state=state, output=output, exit_code=proc.returncode if proc else None)
            self.audit(state, job['id'])
            self.db.commit()
        return True

    def loop(self):
        while not self.stop.is_set():
            if not self.run_one(): self.stop.wait(0.2)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b'\n'):
                raise ValueError('Request too large or incomplete')
            request = json.loads(raw)
            result = {'result': self.server.worker.call(request['name'], request.get('arguments', {}))}
        except Exception as exc:
            result = {'error': str(exc)}
        self.wfile.write(json.dumps(result).encode() + b'\n')


def main():
    os.umask(0o077)
    with open(os.environ.get('MASTER_CONFIG', '/etc/nullink-master/config.json')) as f:
        config = json.load(f)
    worker = Worker(config)
    path = config.get('socket', '/run/nullink-master/worker.sock')
    Path(path).unlink(missing_ok=True)
    # Local socket group is the admin gateway boundary; never expose this over TCP.
    with socketserver.ThreadingUnixStreamServer(path, Handler) as server:
        server.worker = worker
        os.chmod(path, 0o660)
        runner = threading.Thread(target=worker.loop)
        runner.start()
        def stop(signum, frame):
            worker.stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try: server.serve_forever()
        finally:
            worker.stop.set()
            runner.join()
            worker.close()
            Path(path).unlink(missing_ok=True)


if __name__ == '__main__':
    main()
