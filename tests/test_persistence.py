import json
import sqlite3
import pytest
from fastapi.testclient import TestClient
from patchproof import api, service
from patchproof.storage import Store
from test_api import TOKEN, HEADERS, scan, wait


def client(path, fixture=None, provider=None):
    return TestClient(api.create_app(api.Settings(token=TOKEN, database_path=str(path), fixture_origin=fixture),
                                    provider=provider), base_url='http://127.0.0.1:8000', headers=HEADERS)


def test_persistence_rechecks_and_download_after_restart(tmp_path, fixture_site):
    url, state = fixture_site
    path = tmp_path/'history.sqlite3'
    with client(path,url) as first:
        original=scan(first,url)
        finding=original['findings'][0]
        spec=first.get(f"/v1/findings/{finding['id']}/spec").json()
    state['csp']="default-src 'self'"
    with client(path,url) as second:
        assert state['requests']==1
        restored=second.get('/v1/jobs/'+original['id']).json()
        assert restored['report']==original['report']
        assert restored['findings'][0]['id']==finding['id']
        assert second.get(f"/v1/findings/{finding['id']}/spec").json()==spec
        check=second.post(f"/v1/findings/{finding['id']}/rechecks",json={}).json()
        result=wait(second,check['id'])
        assert result['report']['result']['status']=='resolved'
        timeline=second.get(f"/v1/findings/{finding['id']}/rechecks").json()['items']
        assert timeline[0]['id']==result['id']
        assert second.get('/v1/jobs/'+original['id']).json()['report']==original['report']
    # Removing fixture permission on restart applies to the stored spec too.
    with client(path) as third:
        check=third.post(f"/v1/findings/{finding['id']}/rechecks",json={}).json()
        assert wait(third,check['id'])['report']['result']['status']=='unverified'
        assert state['requests']==2


def test_newest_first_keyset_pagination(tmp_path, fixture_site):
    url,_=fixture_site
    with client(tmp_path/'db.sqlite3',url) as app:
        ids=[scan(app,url)['id'] for _ in range(4)]
        first=app.get('/v1/scans?limit=2').json()
        assert [j['id'] for j in first['items']]==list(reversed(ids[2:]))
        extra=scan(app,url)['id']
        second=app.get('/v1/scans',params={'limit':2,'before':first['next_cursor']}).json()
        assert [j['id'] for j in second['items']]==list(reversed(ids[:2]))
        assert second['next_cursor'] is None
        assert app.get('/v1/scans').json()['items'][0]['id']==extra
        assert first['items'][0]['finding_count']==1
        for params in ({'limit':0},{'limit':51},{'before':'unknown'}):
            assert app.get('/v1/scans',params=params).status_code==422


def test_interrupted_recovery_preserves_baseline_and_never_resumes(tmp_path, fixture_site):
    url,state=fixture_site
    path=tmp_path/'db.sqlite3'
    baseline=service.scan(url,allow_local=True)
    inputs={'target_url':url,'session_cookies':[],'ai':True}
    store=Store(path)
    running=store.create(kind='scan',target=url,inputs=inputs)
    store.running(running)
    store.checkpoint(running,baseline)
    queued=store.create(kind='scan',target=url,inputs=inputs)
    finding=store.get(running)['findings'][0]
    recheck=store.create(kind='recheck',target=url,inputs=finding['spec'],finding_id=finding['id'])
    store.running(recheck)
    store.close()
    class Fake:
        calls=0
        def complete(self,*args):
            self.calls+=1
            raise TimeoutError('SECRET')
    provider=Fake()
    with client(path,provider=provider) as app:
        assert state['requests']==1 and provider.calls==0
        for job_id in (running,queued,recheck):
            assert app.get('/v1/jobs/'+job_id).json()['state']=='interrupted'
        saved=app.get('/v1/jobs/'+running).json()
        assert saved['report']['baseline']==baseline.model_dump(mode='json')
        assert saved['findings'][0]['latest_recheck']['state']=='interrupted'
        assert saved['findings'][0]['latest_recheck']['report'] is None
        assert app.get(f"/v1/findings/{finding['id']}/spec").status_code==200
        # Explicit retry revalidates original inputs and the current (no-loopback) policy.
        retried=app.post('/v1/jobs/'+running+'/retry',json={})
        assert retried.status_code==202
        retry=wait(app,retried.json()['id'])
        assert retry['retry_of']==running and retry['id']!=running
        assert retry['report']['baseline']['status']=='unverified'
        assert state['requests']==1 and provider.calls==0
        replay=app.post('/v1/jobs/'+recheck+'/retry',json={})
        assert wait(app,replay.json()['id'])['report']['result']['status']=='unverified'
        assert app.get('/v1/jobs/'+running).json()['state']=='interrupted'
        assert app.post('/v1/jobs/'+retry['id']+'/retry',json={}).status_code==409
        assert app.post('/v1/jobs/'+running+'/retry',json={'allow_local':True}).status_code==422


def test_baseline_checkpoint_before_ai_and_saved_records_redacted(tmp_path, fixture_site):
    url,_=fixture_site
    path=tmp_path/'history.sqlite3'
    class Fake:
        def complete(self,messages,tools):
            # Read committed data from a separate connection during the model call.
            with sqlite3.connect(path) as db:
                row=db.execute('SELECT baseline_json,state FROM jobs').fetchone()
                assert row[0] is not None and row[1]=='running'
                assert db.execute('SELECT count(*) FROM findings').fetchone()[0]==1
            assert url not in json.dumps(messages)
            raise TimeoutError('SECRET_PROVIDER_TRANSCRIPT')
    with client(path,url,Fake()) as app:
        job=scan(app,url,ai=True)
        assert job['report']['investigation']['ai_status']=='provider_error'
    with sqlite3.connect(path) as db:
        dump='\n'.join(db.iterdump())
    assert 'SECRET' not in dump and TOKEN not in dump
    assert 'messages' not in dump and 'Authorization' not in dump


def test_atomic_completion_and_immutable_original(tmp_path,fixture_site):
    url,_=fixture_site
    baseline=service.scan(url,allow_local=True)
    store=Store(tmp_path/'db.sqlite3')
    try:
        job=store.create(kind='scan',target=url,inputs={'target_url':url,'ai':False,'session_cookies':[]})
        store.running(job)
        with pytest.raises(TypeError):
            store.complete(job,{'invalid':object()},baseline)
        assert store.get(job)['report'] is None and store.get(job)['findings']==[]
        report={'baseline':baseline.model_dump(mode='json'),'investigation':None}
        store.complete(job,report,baseline)
        with pytest.raises(sqlite3.IntegrityError), store.db:
            store.db.execute("UPDATE jobs SET report_json='{}' WHERE id=?",(job,))
        assert store.get(job)['report']==report
        with pytest.raises(sqlite3.IntegrityError),store.db:
            store.db.execute("UPDATE findings SET data_json='{}'")
    finally:
        store.close()


def test_schema_initialization_lock_and_future_version(tmp_path):
    path=tmp_path/'db.sqlite3'
    store=Store(path)
    assert store.db.execute('PRAGMA user_version').fetchone()[0]==1
    with pytest.raises(ValueError,match='already in use'):
        Store(path,recover=True)
    store.close()
    initialized=Store(path)
    initialized.close()
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA user_version=99')
    with pytest.raises(ValueError,match='Unsupported database schema'):
        Store(path)


def test_single_worker_configuration():
    with pytest.raises(ValueError):
        api.Settings(token=TOKEN, workers=2)


def test_failed_recheck_does_not_reuse_previous_resolved_result(tmp_path, fixture_site, monkeypatch):
    url,state=fixture_site
    with client(tmp_path/'db.sqlite3',url) as app:
        original=scan(app,url)
        finding=original['findings'][0]
        state['csp']="default-src 'self'"
        route=f"/v1/findings/{finding['id']}/rechecks"
        resolved=wait(app,app.post(route,json={}).json()['id'])
        assert resolved['report']['result']['status']=='resolved'
        def fail(*args,**kwargs):
            raise RuntimeError('SECRET')
        monkeypatch.setattr(service,'execute',fail)
        failed=wait(app,app.post(route,json={}).json()['id'])
        assert failed['state']=='failed' and failed['report'] is None
        report=app.get('/v1/jobs/'+original['id']).json()
        assert report['report']==original['report']
        assert report['findings'][0]['latest_recheck']['state']=='failed'
        assert report['findings'][0]['latest_recheck']['report'] is None
        page=app.get(route,params={'limit':1}).json()
        assert page['items'][0]['state']=='failed'
        previous=app.get(route,params={'limit':1,'before':page['next_cursor']}).json()
        assert previous['items'][0]['report']['result']['status']=='resolved'
        assert 'SECRET' not in json.dumps([failed,report,page])
