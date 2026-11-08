"""Run with an installed wheel's interpreter, from outside the checkout."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

extra = sys.argv[1] if len(sys.argv) > 1 else 'core'
for module, required_extra in [('fastapi', 'api'), ('playwright', 'browser'), ('pytest', 'dev')]:
    assert (importlib.util.find_spec(module) is not None) == (extra == required_extra)
import patchproof
assert Path(patchproof.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
from patchproof import __version__
assert __version__ == '0.1.0'
fixed = False
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Set-Cookie', 'sid=RELEASE_SECRET_COOKIE')
        if fixed:
            self.send_header('Content-Security-Policy', "default-src 'self'")
        self.end_headers()
        self.wfile.write(b'RELEASE_SECRET_BODY')
    def log_message(self, *_): pass

env = {k: v for k, v in os.environ.items() if not k.startswith('OPENROUTER_') and k != 'PYTHONPATH'}
cli = str(Path(sys.executable).with_name('patchproof'))
def run(args, code=0):
    result = subprocess.run([cli, *args], env=env, capture_output=True, text=True)
    assert result.returncode == code, result.stdout + result.stderr
    assert 'RELEASE_SECRET' not in result.stdout + result.stderr
    return result.stdout

for command in [[], ['scan'], ['replay'], ['investigate']]:
    run([*command, '--help'])
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
url = f'http://127.0.0.1:{server.server_port}/'
try:
    with tempfile.TemporaryDirectory() as directory:
        spec = str(Path(directory) / 'check.json')
        result = json.loads(run(['scan', url, '--allow-local', '--format', 'json', '--export-check', spec]))
        assert result['status'] == 'still_present'
        assert 'RELEASE_SECRET' not in Path(spec).read_text()
        run(['replay', spec, '--allow-local', '--format', 'json'], 1)
        ai = json.loads(run(['investigate', url, '--allow-local', '--format', 'json']))
        assert ai['ai_status'] == 'not_configured' and ai['baseline']['findings']
        fixed = True
        assert json.loads(run(['replay', spec, '--allow-local', '--format', 'json']))['status'] == 'resolved'
        run(['replay', spec, '--format', 'json'], 2)
        server.shutdown(); server.server_close(); thread.join()
        assert json.loads(run(['replay', spec, '--allow-local', '--format', 'json'], 2))['status'] == 'unverified'
        if extra == 'api':
            subprocess.run([sys.executable, '-m', 'patchproof.storage', 'init', '--database', str(Path(directory)/'history.sqlite3')], check=True)
            from patchproof.api import create_app, Settings
            from fastapi.testclient import TestClient
            app = create_app(Settings(token='release-test-' + 'x' * 32, database_path=str(Path(directory)/'history.sqlite3')))
            assert app.version == __version__
            with TestClient(app, base_url='http://127.0.0.1:8000') as client:
                assert client.get('/v1/capabilities', headers={'Authorization': 'Bearer release-test-' + 'x' * 32}).status_code == 200
            import sqlite3
            with sqlite3.connect(Path(directory)/'history.sqlite3') as db:
                assert db.execute('PRAGMA user_version').fetchone()[0] == 1
            subprocess.run([sys.executable, '-m', 'uvicorn', '--help'], check=True, stdout=subprocess.DEVNULL)
finally:
    server.shutdown(); server.server_close()
print(f'PASS installed {extra}: CLI help, scan, evidence, export, replay 1/0/2, missing AI fallback')
