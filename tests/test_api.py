import json
import threading
import time
import httpcore
import pytest
from fastapi.testclient import TestClient
from patchproof import api, service

TOKEN = 'local-test-credential-' + 'x' * 32
HEADERS = {'Authorization': 'Bearer ' + TOKEN, 'Origin': 'http://localhost:3000'}


def client_for(fixture_origin=None, provider=None, **kwargs):
    app = api.create_app(api.Settings(token=TOKEN, fixture_origin=fixture_origin, **kwargs), provider=provider)
    return TestClient(app, base_url='http://127.0.0.1:8000', headers=HEADERS)


def wait(client, job_id):
    for _ in range(200):
        response = client.get('/v1/jobs/' + job_id)
        assert response.status_code == 200
        data = response.json()
        if data['state'] in ('completed', 'failed'):
            return data
        time.sleep(.01)
    pytest.fail('Job did not finish')


def scan(client, target, **options):
    response = client.post('/v1/scans', json={'target_url': target, **options})
    assert response.status_code == 202, response.text
    return wait(client, response.json()['id'])


def test_api_workflow_download_recheck(fixture_site, monkeypatch):
    url, state = fixture_site
    with client_for(url) as client:
        job = scan(client, url)
        assert job['state'] == 'completed'
        finding = job['findings'][0]
        downloaded = client.get('/v1/findings/' + finding['id'] + '/spec')
        assert downloaded.status_code == 200
        assert 'attachment' in downloaded.headers['content-disposition']
        assert downloaded.json()['schema_version'] == '1'
        assert service.validate_spec(downloaded.json())
        def recheck():
            response = client.post('/v1/findings/' + finding['id'] + '/rechecks', json={})
            assert response.status_code == 202
            return wait(client, response.json()['id'])
        still = recheck()
        assert still['report']['result']['status'] == 'still_present'
        assert still['original_finding_id'] == finding['id']
        state['csp'] = "default-src 'self'"
        fixed = recheck()
        assert fixed['report']['result']['status'] == 'resolved'
        latest = client.get('/v1/jobs/' + job['id']).json()['findings'][0]['latest_recheck']
        assert latest['id'] == fixed['id']
        assert job['findings'][0]['run']['observed_condition'] is False
        def unavailable(*args):
            raise httpcore.ConnectError('SECRET_ERROR')
        monkeypatch.setattr(httpcore.ConnectionPool, 'handle_request', unavailable)
        unverified = recheck()
        assert unverified['report']['result']['status'] == 'unverified'
        assert 'SECRET' not in json.dumps([job, fixed, unverified, downloaded.json()])
        assert state['requests'] == 3


def test_default_blocks_loopback_and_exact_fixture_origin(fixture_site):
    url, state = fixture_site
    with client_for() as client:
        blocked = scan(client, url)
        assert blocked['report']['baseline']['status'] == 'unverified'
        assert 'blocked' in blocked['report']['baseline']['run']['reason']
        invalid = client.post('/v1/scans', json={'target_url':url,'allow_local':True})
        assert invalid.status_code == 422
    with client_for('http://127.0.0.1:1') as client:
        assert scan(client,url)['report']['baseline']['status'] == 'unverified'
    assert state['requests'] == 0


@pytest.mark.parametrize('change,expected', [({'Authorization':''},401), ({'Host':'evil.example'},403), ({'Origin':'https://evil.example'},403)])
def test_boundaries(change,expected):
    with client_for() as client:
        assert client.post('/v1/scans',json={'target_url':'https://example.com'},headers=change).status_code == expected


def test_validation_is_redacted_and_body_bounded():
    with client_for() as client:
        result = client.post('/v1/scans',json={'target_url':'https://user:SECRET@example.com'})
        assert result.status_code == 422 and 'SECRET' not in result.text
        assert client.post('/v1/scans',content='x'*8193,headers={'content-type':'application/json'}).status_code == 413
        assert client.post('/v1/scans',content='{}',headers={'content-type':'text/plain'}).status_code == 415
        assert client.get('/v1/capabilities').headers.get('access-control-allow-origin') is None
        assert client.get('/v1/jobs/unknown').status_code == 404
        assert client.get('/v1/findings/unknown/spec').status_code == 404


def test_job_runner_immediate_bounded_and_expiring(fixture_site, monkeypatch):
    url, _ = fixture_site
    entered, release = threading.Event(), threading.Event()
    real_scan = service.scan
    def pause(*args, **kwargs):
        entered.set()
        release.wait(5)
        return real_scan(*args, **kwargs)
    monkeypatch.setattr(service, 'scan', pause)
    with client_for(url, workers=1,pending_limit=1,store_limit=1,ttl=1) as client:
        try:
            response=client.post('/v1/scans',json={'target_url':url})
            assert response.status_code == 202
            job_id=response.json()['id']
            assert entered.wait(1)
            assert client.get('/v1/jobs/'+job_id).json()['state']=='running'
            assert client.post('/v1/scans',json={'target_url':url}).status_code==429
        finally:
            release.set()
        job=wait(client,job_id)
        finding_id=job['findings'][0]['id']
        assert client.post('/v1/scans',json={'target_url':url}).status_code==429
        store=client.app.state.jobs
        with store.lock:
            store.jobs[job_id]['_finished'] -= 2
        assert client.get('/v1/jobs/'+job_id).status_code==404
        assert client.get('/v1/findings/'+finding_id+'/spec').status_code==404
        assert client.post('/v1/scans',json={'target_url':url}).status_code==202


def test_failed_job_does_not_leak_error(fixture_site,monkeypatch):
    url,_=fixture_site
    def fail(*args,**kwargs): raise RuntimeError('SECRET')
    monkeypatch.setattr(service,'scan',fail)
    with client_for(url) as client:
        result=scan(client,url)
        assert result['state']=='failed' and 'SECRET' not in json.dumps(result)


def test_fake_ai_baseline_survives_failure(fixture_site):
    url,_=fixture_site
    class Fake:
        calls=0
        def complete(self,messages,tools):
            self.calls+=1
            assert url not in json.dumps(messages)
            raise TimeoutError('SECRET_KEY')
    provider=Fake()
    with client_for(url,provider=provider) as client:
        deterministic=scan(client,url)
        assert provider.calls==0 and deterministic['report']['investigation'] is None
        result=scan(client,url,ai=True)
        assert provider.calls==1
        assert result['findings']
        assert result['report']['investigation']['ai_status']=='provider_error'
        assert 'SECRET' not in json.dumps(result)


def test_ai_unconfigured_and_browser_cannot_supply_key(fixture_site,monkeypatch):
    monkeypatch.delenv('OPENROUTER_API_KEY',raising=False)
    monkeypatch.delenv('OPENROUTER_MODEL',raising=False)
    url,_=fixture_site
    with client_for(url) as client:
        assert scan(client,url,ai=True)['report']['investigation']['ai_status']=='not_configured'
        response=client.post('/v1/scans',json={'target_url':url,'api_key':'SECRET'})
        assert response.status_code==422 and 'SECRET' not in response.text


@pytest.mark.parametrize('value',['http://10.0.0.1:8765','http://localhost:8765','http://127.0.0.1:8765/path'])
def test_fixture_configuration_must_be_literal_loopback_origin(value):
    with pytest.raises(ValueError): api.Settings(token=TOKEN,fixture_origin=value)
