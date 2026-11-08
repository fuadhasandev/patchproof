import json
import os
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner
from patchproof import browser, service
from patchproof.browser_worker import approved, sandbox_available
from patchproof.cli import app
from patchproof.models import BrowserCheckSpec, BrowserEvidence, Evidence


def snapshot(**kwargs):
    return Evidence(is_https=True, browser=BrowserEvidence(availability='available', **kwargs))


@pytest.mark.parametrize('data,status', [
    ({'insecure_references': 1}, 'still_present'),
    ({'navigation_ok': True, 'coverage_complete': True}, 'resolved'),
    ({'navigation_ok': True, 'policy_blocked': 1}, 'unverified'),
    ({'limit_reached': True}, 'unverified'),
    ({'navigation_ok': True, 'coverage_complete': True, 'limit_reached': True}, 'unverified'),
    ({'navigation_ok': True, 'coverage_complete': True, 'policy_blocked': 1}, 'unverified'),
    ({}, 'unverified'),
])
def test_pure_detector(data, status):
    result = service.evaluate(BrowserCheckSpec(target_url='https://example.com/'), snapshot(**data), None, replaying=True)
    assert result.status == status


@pytest.mark.parametrize('change', [
    {'parameters': {'profile': 'anything'}}, {'parameters': {'profile': 'chromium-static-v1', 'allow_local': 'true'}},
    {'detector_version': '2'}, {'method': 'POST'}, {'schema_version': '4'}, {'rule_id': 'browser.other'},
])
def test_reject_browser_spec_scope(change):
    payload = BrowserCheckSpec(target_url='https://example.com/').model_dump()
    payload.update(change)
    with pytest.raises(ValueError):
        service.validate_spec(payload)


@pytest.mark.parametrize('url,method,allowed', [
    ('https://example.com/image.png', 'GET', True),
    ('http://example.com/image.png', 'GET', False),
    ('https://third.example/image.png', 'GET', False),
    ('https://example.com:444/image.png', 'GET', False),
    ('https://example.com/image.png?SECRET=1', 'GET', False),
    ('https://example.com/image.png', 'POST', False),
    ('file:///etc/passwd', 'GET', False),
    ('https://127.0.0.1/image.png', 'GET', False),
])
def test_broker_origin_scope(url, method, allowed):
    assert approved(url, 'https://example.com/', method) is allowed


def test_optional_browser_baseline_cli(fixture_site, monkeypatch):
    url, state = fixture_site
    monkeypatch.setattr(browser.sys, 'platform', 'unsupported')
    result = CliRunner().invoke(app, ['scan', url, '--allow-local', '--browser', '--format', 'json'])
    assert result.exit_code == 0  # HTTP profile skip, CSP behavior retained
    data = json.loads(result.stdout)
    assert len(data['checks']) == 4
    assert data['checks'][-1]['status'] == 'skipped'
    assert state['requests'] == 1
    assert browser.collect_browser('https://example.com/')[0].browser.availability == 'unavailable'
    assert 'SECRET' not in result.stdout


def test_browser_replay_uses_collector(monkeypatch):
    monkeypatch.setattr(browser, 'collect_browser', lambda *a, **k: (snapshot(), 'Unavailable.'))
    assert service.execute(BrowserCheckSpec(target_url='https://example.com/')).status == 'unverified'


def test_browser_never_enters_model_payload(monkeypatch):
    from patchproof.investigation import investigate
    from patchproof.models import ScanResult
    check = service.evaluate(BrowserCheckSpec(target_url='https://example.com/'), snapshot(insecure_references=1), None)
    baseline = ScanResult(**check.model_dump(exclude={'finding', 'run'}), run=check.run,
                          finding=check.finding, checks=(check,), findings=(check.finding,))
    monkeypatch.setattr(service, 'scan', lambda *a, **k: baseline)
    class Fake:
        def complete(self, messages, tools):
            assert 'browser.' not in json.dumps(messages)
            assert 'insecure_references' not in json.dumps(messages)
            raise TimeoutError
    result = investigate('https://example.com/', provider=Fake(), browser=True)
    assert result.baseline.findings == (check.finding,)
    assert result.evidence == {}


@pytest.fixture
def https_site(tmp_path, monkeypatch):
    # Opt in to real Chromium integration; unit/default regression tests require
    # neither Chromium nor internet. Certificates are generated and trusted only
    # by this test process/broker, never installed in a system trust store.
    if os.environ.get('PATCHPROOF_TEST_BROWSER') != '1':
        pytest.skip('Set PATCHPROOF_TEST_BROWSER=1 for isolated Chromium integration')
    if sys.platform != 'darwin':
        pytest.fail('Requested browser integration requires macOS controlled egress')
    import playwright  # Explicit opt-in must fail if the extra is missing.
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', '2', '-subj', '/CN=127.0.0.1', '-addext',
                    'subjectAltName=IP:127.0.0.1,DNS:localhost'], check=True, capture_output=True)
    monkeypatch.setenv('PATCHPROOF_BROWSER_CA_FILE', str(cert))
    monkeypatch.setenv('SSL_CERT_FILE', str(cert))
    state = {'body': '<p>fixed</p>', 'requests': [], 'status': 200}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state['requests'].append(self.path)
            self.send_response(state['status'])
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Security-Policy', "default-src * 'unsafe-inline'")
            self.send_header('Strict-Transport-Security', 'max-age=1')
            self.send_header('Set-Cookie', 'session=SECRET_COOKIE')
            self.end_headers()
            self.wfile.write(state['body'].encode())
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'https://127.0.0.1:{server.server_port}/', state
    server.shutdown(); server.server_close(); thread.join()


def test_real_browser_export_fix_replay(https_site, tmp_path):
    url, state = https_site
    assert sandbox_available()
    state['body'] = '<img src="http://outside.invalid/SECRET_PATH?secret=SECRET_QUERY"><p>SECRET_BODY</p>'
    cli = CliRunner().invoke(app, ['scan', url, '--allow-local', '--browser', '--format', 'json'])
    assert cli.exit_code == 0, cli.stdout
    from patchproof.models import ScanResult
    result = ScanResult.model_validate_json(cli.stdout)
    check = result.checks[-1]
    assert check.status == 'still_present', check.model_dump_json()
    assert check.run.evidence.browser.insecure_references == 1
    assert check.run.evidence.browser.http_loads == 0
    spec_path = tmp_path / 'check.json'
    service.export_check(check.finding, spec_path)
    assert service.load_spec(spec_path).schema_version == '3'
    assert 'SECRET' not in result.model_dump_json() + spec_path.read_text()
    assert set(state['requests']) == {'/'}  # no third-party traffic
    state['body'] = '<p>fixed</p>'
    replayed = CliRunner().invoke(app, ['replay', str(spec_path), '--allow-local', '--format', 'json'])
    assert replayed.exit_code == 0, replayed.stdout
    assert json.loads(replayed.stdout)['status'] == 'resolved'
    assert service.replay(spec_path).status == 'unverified'  # spec grants nothing


def test_real_out_of_scope_and_redirect_coverage(https_site):
    url, state = https_site
    state['body'] = '<img src="https://outside.invalid/secret"><iframe src="/frame"></iframe>'
    result = service.execute(BrowserCheckSpec(target_url=url), allow_local=True)
    assert result.status == 'unverified'
    assert result.run.evidence.browser.policy_blocked >= 1
    assert set(state['requests']) == {'/'}
    state['status'] = 302
    assert service.execute(BrowserCheckSpec(target_url=url), allow_local=True).status == 'unverified'


def test_real_https_upgrade_or_block(https_site):
    url, state = https_site
    state['body'] = '<img src="http://outside.invalid/image.png">'
    result = service.execute(BrowserCheckSpec(target_url=url), allow_local=True)
    b = result.run.evidence.browser
    assert result.status == 'still_present'
    assert b.https_upgrades or b.browser_blocked, b
    assert b.http_loads == 0


def test_browser_timeout_kills_owned_processes(monkeypatch, tmp_path):
    killed = []
    class Process:
        pid = 987654
        returncode = None
        def communicate(self, *args, **kwargs):
            raise subprocess.TimeoutExpired('worker', 20)
        def wait(self): return -9
    monkeypatch.setattr(browser.sys, 'platform', 'darwin')
    monkeypatch.setattr(browser.os.path, 'isfile', lambda p: True)
    monkeypatch.setattr(browser.subprocess, 'Popen', lambda *a, **k: Process())
    monkeypatch.setattr(browser.os, 'killpg', lambda pid, sig: killed.append(pid))
    evidence, reason = browser.collect_browser('https://example.com/')
    assert evidence.browser.limit_reached
    assert not evidence.browser.coverage_complete
    assert killed == [987654]
    assert browser._SLOT.acquire(blocking=False)
    browser._SLOT.release()


def test_real_request_budget(https_site):
    url, state = https_site
    state['body'] = ''.join(f'<img src="/image{i}">' for i in range(40))
    result = service.execute(BrowserCheckSpec(target_url=url), allow_local=True)
    assert result.status == 'unverified'
    assert result.run.evidence.browser.limit_reached
    assert len(state['requests']) <= 32


def test_real_api_browser_persistence_and_redaction(https_site, tmp_path):
    from fastapi.testclient import TestClient
    from patchproof.api import create_app, Settings
    import time
    url, state = https_site
    token = 'test-token-' + 'x' * 32
    settings = Settings(token=token, fixture_origin=url, database_path=str(tmp_path / 'history.sqlite3'))
    headers = {'Authorization': 'Bearer ' + token, 'Origin': 'http://localhost:3000'}
    class Fake:
        calls = 0
        def complete(self, messages, tools):
            self.calls += 1
            assert 'browser.' not in json.dumps(messages)
            assert 'SECRET' not in json.dumps(messages)
            raise TimeoutError('SECRET_PROVIDER')
    provider = Fake()
    state['body'] = '<img src="http://outside.invalid/SECRET_PATH?SECRET_QUERY">SECRET_BODY'
    def wait(client, jid):
        for _ in range(500):
            data = client.get('/v1/jobs/' + jid).json()
            if data['state'] in ('completed', 'failed'): return data
            time.sleep(.1)
        pytest.fail('Timed out waiting for browser job')
    with TestClient(create_app(settings, provider=provider), base_url='http://127.0.0.1:8000', headers=headers) as client:
        created = client.post('/v1/scans', json={'target_url': url.rstrip('/'), 'browser': True, 'ai': True}).json()
        job = wait(client, created['id'])
        assert job['state'] == 'completed', job
        assert provider.calls == 1
        finding = next(f for f in job['findings'] if f['spec']['rule_id'].startswith('browser.'))
        assert 'SECRET' not in json.dumps(job)
    state['body'] = '<p>Fixed</p>'
    with TestClient(create_app(settings), base_url='http://127.0.0.1:8000', headers=headers) as client:
        spec = client.get('/v1/findings/' + finding['id'] + '/spec').json()
        assert service.validate_spec(spec).schema_version == '3'
        created = client.post('/v1/findings/' + finding['id'] + '/rechecks', json={}).json()
        assert wait(client, created['id'])['report']['result']['status'] == 'resolved'
        original = client.get('/v1/jobs/' + job['id']).json()['findings'][0]
        assert original['run']['observed_condition'] is False
        assert original['latest_recheck']['report']['result']['status'] == 'resolved'
        dump = '\n'.join(client.app.state.jobs.store.db.iterdump())
        assert 'SECRET' not in dump
        assert token not in dump


def test_cancellation_cleans_chromium_group_and_environment(monkeypatch):
    from pathlib import Path
    killed, captured = [], {}
    class Process:
        pid = 987654
        def communicate(self, *args, **kwargs): raise KeyboardInterrupt
        def wait(self): return -9
    def spawn(*args, **kwargs):
        captured.update(kwargs['env'])
        Path(captured['PATCHPROOF_BROWSER_PID_FILE']).write_text('987655')
        return Process()
    monkeypatch.setenv('OPENROUTER_API_KEY', 'SECRET_KEY')
    monkeypatch.setenv('DEBUG', 'pw:*')
    monkeypatch.setattr(browser.sys, 'platform', 'darwin')
    monkeypatch.setattr(browser.os.path, 'isfile', lambda p: True)
    monkeypatch.setattr(browser.subprocess, 'Popen', spawn)
    monkeypatch.setattr(browser.os, 'killpg', lambda pid, sig: killed.append(pid))
    with pytest.raises(KeyboardInterrupt):
        browser.collect_browser('https://example.com/')
    assert killed == [987654, 987655]
    assert 'OPENROUTER_API_KEY' not in captured and 'DEBUG' not in captured
    assert not Path(captured['TMPDIR']).exists()
    assert browser._SLOT.acquire(blocking=False)
    browser._SLOT.release()


def test_unavailable_browser_keeps_https_baseline(monkeypatch):
    monkeypatch.setattr(service, 'collect', lambda *a, **k: (Evidence(is_https=True, status_code=200,
                      is_html=True, csp_present=False, hsts_present=True), None))
    monkeypatch.setattr(browser, 'collect_browser', lambda *a, **k: browser.unavailable('Browser unavailable.'))
    result = service.scan('https://example.com/', browser=True)
    assert result.findings[0].spec.schema_version == '1'
    assert result.checks[-1].status == 'unverified'
    assert result.status == 'unverified'
