import socket
from fastapi.testclient import TestClient
from patchproof.basic_api import create_app
from patchproof import collector

TOKEN = 'basic-test-secret-' * 3


def client():
    return TestClient(create_app(TOKEN), headers={'Authorization': 'Bearer ' + TOKEN})


def test_basic_fixture(fixture_site, monkeypatch):
    url, state = fixture_site
    # Test-only routing of a public name to the controlled fixture; no production bypass.
    real = collector.resolve
    def resolve(host, port, allow_local):
        assert allow_local is False
        if host == 'fixture.example':
            return socket.getaddrinfo('127.0.0.1', int(url.split(':')[2].split('/')[0]), type=socket.SOCK_STREAM)[0]
        return real(host, port, allow_local)
    monkeypatch.setattr(collector, 'resolve', resolve)
    c = client()
    for status, csp, expected in [(200, None, 'still_present'), (200, "default-src 'self'", 'resolved'), (302, None, 'unverified')]:
        state.update(status=status, csp=csp)
        response = c.post('/v1/basic-reports', json={'target_url': 'http://fixture.example/'})
        assert response.status_code == 200
        checks = response.json()['report']['baseline']['checks']
        assert checks[0]['status'] == expected
        assert checks[1]['status'] == ('skipped' if status == 200 else 'unverified')
        assert 'SECRET' not in response.text
    assert state['requests'] == 3


def test_auth_limits_and_private_destinations(fixture_site):
    url, state = fixture_site
    c = client()
    assert c.get('/health').status_code == 200
    assert c.post('/v1/basic-reports', headers={'Authorization': 'bad'}, json={}).status_code == 401
    for target in [url, 'http://10.0.0.1/', 'http://[::1]/', 'http://169.254.169.254/']:
        r = c.post('/v1/basic-reports', json={'target_url': target})
        assert r.json()['report']['baseline']['checks'][0]['status'] == 'unverified'
    assert state['requests'] == 0
    assert c.post('/v1/basic-reports', json={'target_url': url, 'allow_local': True}).status_code == 422
    assert c.post('/v1/basic-reports', content='x'*4097, headers={'Content-Type':'application/json'}).status_code == 413
    for _ in range(24):
        c.post('/v1/basic-reports', json={'target_url':'invalid'})
    r = c.post('/v1/basic-reports', json={'target_url':url})
    assert r.status_code == 429 and r.headers['retry-after'] == '60'


def test_capacity_and_timeout(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    import httpcore
    from patchproof import service
    entered, release = Event(), Event()
    original = service.scan
    def wait(target):
        entered.set()
        assert release.wait(5)
        return original(target)
    monkeypatch.setattr(service, 'scan', wait)
    def timeout(*args, **kwargs):
        raise httpcore.ReadTimeout('PRIVATE_DETAIL')
    monkeypatch.setattr(collector.PolicyBackend, 'connect_tcp', timeout)
    c = client()
    def submit():
        return c.post('/v1/basic-reports', json={'target_url':'https://fixture.example/'})
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = []
        try:
            for _ in range(4):
                entered.clear()
                futures.append(pool.submit(submit))
                assert entered.wait(5)
            assert submit().status_code == 429
        finally:
            release.set()
        for future in futures:
            response = future.result()
            assert response.status_code == 200
            assert response.json()['report']['baseline']['checks'][0]['status'] == 'unverified'
            assert 'PRIVATE_DETAIL' not in response.text
    assert submit().status_code == 200  # slots released after timeout
