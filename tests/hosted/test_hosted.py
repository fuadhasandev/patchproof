import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest
from sqlalchemy import select,update,text,func
from patchproof.hosted import db,store
from patchproof.hosted.queue import Queue
from patchproof.hosted.worker import Worker
from patchproof import collector,service
from patchproof.models import Evidence


def submission(h,project,target,**options):
    body={'project_id':project,'target_id':target,'target_url':'https://fixture.example/','ai':False,'browser':False,'session_cookies':[],**options}
    r=h.client.post('/v2/scans',headers=h.headers(),json=body)
    assert r.status_code==202,r.text
    return r.json()['id'],body


def fake_target(monkeypatch,*,csp=False):
    state={'csp':csp,'requests':0}
    def collect(*a,**k):
        state['requests']+=1
        return Evidence(status_code=200,is_https=True,is_html=True,csp_present=state['csp'],hsts_present=True),None
    monkeypatch.setattr(collector,'_collect',collect)
    return state


def test_ownership_idempotency_and_workflow(harness,monkeypatch):
    h=harness; uid,p,t=h.create(); h.create('bob')
    state=fake_target(monkeypatch)
    job,body=submission(h,p,t)
    repeated=h.client.post('/v2/scans',headers=h.headers(),json=body)
    assert repeated.json()['id']==job
    changed=h.client.post('/v2/scans',headers=h.headers(),json={**body,'ai':True});assert changed.status_code==409
    for path in [f'/v2/jobs/{job}',f'/v2/projects/{p}/scans',f'/v2/projects/{p}/targets']:
        assert h.client.get(path,headers=h.headers('bob')).status_code==404
    assert h.client.post(f'/v2/jobs/{job}/cancel',headers=h.headers('bob'),json={}).status_code==404
    assert h.client.post('/v2/scans',headers=h.headers('bob'),json=body).status_code==404
    Worker(h.engine,h.settings).once()
    data=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert data['state']=='completed',data
    f=data['findings'][0]['id']
    for path in [f'/v2/findings/{f}/spec',f'/v2/findings/{f}/rechecks']:
        assert h.client.get(path,headers=h.headers('bob')).status_code==404
    assert h.client.post(f'/v2/findings/{f}/rechecks',headers=h.headers('bob'),json={}).status_code==404
    spec=h.client.get(f'/v2/findings/{f}/spec',headers=h.headers()).json();assert spec['schema_version']=='1'
    state['csp']=True
    recheck=h.client.post(f'/v2/findings/{f}/rechecks',headers=h.headers(key='recheck'),json={}).json()['id']
    Worker(h.engine,h.settings).once()
    latest=h.client.get('/v2/jobs/'+recheck,headers=h.headers()).json()
    assert latest['report']['result']['status']=='resolved'
    original=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert original['findings'][0]['latest_recheck']['id']==recheck
    assert original['report']['baseline']['status']=='still_present'
    assert state['requests']==2


def test_unverified_expired_revoked_exact_hostname(harness):
    h=harness;uid,p,t=h.create()
    for url in ['https://sub.fixture.example/','https://other.example/','https://127.0.0.1/']:
        r=h.client.post('/v2/scans',headers=h.headers(key=url),json={'project_id':p,'target_id':t,'target_url':url})
        assert r.status_code==403
    with h.engine.begin() as conn: conn.execute(update(db.targets).where(db.targets.c.id==t).values(verified_until=0))
    assert h.client.post('/v2/scans',headers=h.headers(),json={'project_id':p,'target_id':t,'target_url':'https://fixture.example/'}).status_code==403
    challenge=h.client.post(f'/v2/projects/{p}/targets',headers=h.headers(),json={'hostname':'fixture.example'}).json()
    assert h.client.post(f'/v2/targets/{t}/verify',headers=h.headers(),json={}).status_code==403 # old TXT cannot authorize a rotated challenge
    h.records[challenge['record']]=[challenge['value']]
    assert h.client.post(f'/v2/targets/{t}/verify',headers=h.headers(),json={}).status_code==200
    job,_=submission(h,p,t)
    assert h.client.post(f'/v2/targets/{t}/revoke',headers=h.headers(),json={}).status_code==200
    assert Queue(h.engine,h.settings).claim() is None
    assert h.client.get('/v2/jobs/'+job,headers=h.headers()).json()['state']=='failed'


def test_concurrent_submission_and_claim(harness):
    h=harness;uid,p,t=h.create()
    body={'target_url':'https://fixture.example/','session_cookies':[],'ai':False,'browser':False}
    def submit(_):
        with h.engine.begin() as conn:return store.submit(conn,h.settings,uid,p,t,body,'same')['id']
    with ThreadPoolExecutor(max_workers=6) as pool: ids=list(pool.map(submit,range(6)))
    assert len(set(ids))==1
    q=Queue(h.engine,h.settings)
    with ThreadPoolExecutor(max_workers=6) as pool: claimed=list(pool.map(lambda _:q.claim(),range(6)))
    assert len([j for j in claimed if j])==1


def expire(h,job):
    with h.engine.begin() as conn:conn.execute(update(db.jobs).where(db.jobs.c.id==job).values(lease_until=db.now(conn)-1))


def test_recovery_fencing_preserves_budget(harness):
    h=harness;uid,p,t=h.create();job,_=submission(h,p,t);q=Queue(h.engine,h.settings)
    first=q.claim();call=q.reserve(job,first['lease_token'],'target','https://fixture.example/')
    expire(h,job);assert q.claim() is None
    with h.engine.begin() as conn:conn.execute(update(db.jobs).where(db.jobs.c.id==job).values(available_at=0))
    second=q.claim();assert second['attempts']==2
    assert second['target_calls']==1
    with pytest.raises(store.Stopped):q.finish(job,first['lease_token'],report={'result':{'status':'resolved'}})
    with h.engine.connect() as conn:assert conn.scalar(select(db.calls.c.state).where(db.calls.c.id==call))=='uncertain'
    q.finish(job,second['lease_token'],error='Test stopped.')


def test_uncertain_model_never_automatically_repeated(harness,monkeypatch):
    h=harness;uid,p,t=h.create();fake_target(monkeypatch);job,_=submission(h,p,t,ai=True);q=Queue(h.engine,h.settings)
    attempt=q.claim();baseline=service.scan('https://fixture.example/');q.checkpoint(job,attempt['lease_token'],baseline)
    q.reserve(job,attempt['lease_token'],'model','https://fixture.example/')
    expire(h,job);assert q.claim() is None
    saved=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert saved['state']=='interrupted' and saved['report']['baseline']['findings']
    assert saved['model_calls']==1


def test_failed_ai_and_browser_retain_baseline(harness,monkeypatch):
    h=harness;uid,p,t=h.create();fake_target(monkeypatch)
    class Provider:
        def complete(self,*args):raise RuntimeError('SECRET_PROVIDER')
    job,_=submission(h,p,t,ai=True,browser=True)
    Worker(h.engine,h.settings,Provider()).once()
    saved=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert saved['state']=='completed' and saved['report']['baseline']['findings']
    assert saved['report']['investigation']['ai_status']=='provider_error'
    assert saved['report']['browser_result']['status']=='unverified'
    assert saved['target_calls']==saved['model_calls']==1
    with h.engine.connect() as conn:
        assert conn.scalar(select(db.calls.c.state).where(db.calls.c.kind=='model'))=='uncertain'
        assert 'SECRET' not in json.dumps([dict(r) for r in conn.execute(select(db.jobs)).mappings()])


def test_cancel_before_dispatch_and_between_calls(harness,monkeypatch):
    h=harness;uid,p,t=h.create();state=fake_target(monkeypatch);job,_=submission(h,p,t,ai=True)
    q=Queue(h.engine,h.settings);attempt=q.claim()
    assert h.client.post('/v2/jobs/'+job+'/cancel',headers=h.headers(),json={}).status_code==200
    Worker(h.engine,h.settings).execute(attempt)
    assert state['requests']==0
    assert h.client.get('/v2/jobs/'+job,headers=h.headers()).json()['state']=='cancelled'
    body={'target_url':'https://fixture.example/','session_cookies':[],'ai':True,'browser':False}
    with h.engine.begin() as conn:second=store.submit(conn,h.settings,uid,p,t,body,'second')['id']
    class Provider:
        def complete(self,messages,tools):
            h.client.post('/v2/jobs/'+second+'/cancel',headers=h.headers(),json={})
            return {'tool_calls':[{'id':'call1','type':'function','function':{'name':'rerun_check','arguments':json.dumps({'check_id':next(iter(json.loads(messages[1]['content'])['evidence'].values()))['check_id']})}}]}
    Worker(h.engine,h.settings,Provider()).once()
    assert state['requests']==1
    data=h.client.get('/v2/jobs/'+second,headers=h.headers()).json()
    assert data['state']=='cancelled' and data['model_calls']==1 and data['report']['baseline']['findings']


def test_rate_limits_are_atomic(harness):
    h=harness;uid,p,t=h.create()
    def use(_):
        try:
            with h.engine.begin() as conn:store.rate(conn,'test-shared',2,60)
            return True
        except store.Limited:return False
    with ThreadPoolExecutor(max_workers=8) as pool:assert sum(pool.map(use,range(8)))==2


def test_auth_origin_body_and_safe_errors(harness):
    h=harness
    assert h.client.get('/v2/projects').status_code==401
    for changes in [{'exp':1},{'aud':'other'},{'iss':'https://wrong.example'}]:
        assert h.client.get('/v2/projects',headers={'Authorization':'Bearer '+h.token(**changes)}).status_code==401
    assert h.client.post('/v2/projects',headers={**h.headers(),'Origin':'https://evil.invalid'},json={'name':'x'}).status_code==403
    response=h.client.post('/v2/projects',headers=h.headers(),json={'name':'SECRET/INVALID'})
    assert response.status_code==422 and 'SECRET' not in response.text and response.headers['x-request-id']
    assert h.client.post('/v2/projects',headers=h.headers(),json={'name':'X'*9000}).status_code==413


def test_policy_still_blocks_dns_rebinding_and_redirects(harness,monkeypatch):
    h=harness;uid,p,t=h.create()
    import socket
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))])
    job,_=submission(h,p,t)
    Worker(h.engine,h.settings).once()
    report=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert report['report']['baseline']['status']=='unverified'
    assert report['target_calls']==1


def test_revocation_between_ai_and_followup(harness,monkeypatch):
    h=harness;uid,p,t=h.create();state=fake_target(monkeypatch)
    class Provider:
        count=0
        def complete(self,messages,tools):
            self.count+=1
            h.client.post(f'/v2/targets/{t}/revoke',headers=h.headers(),json={})
            records=json.loads(messages[1]['content'])['evidence']
            check=next(iter(records.values()))['check_id']
            return {'tool_calls':[{'id':'c1','type':'function','function':{'name':'rerun_check','arguments':json.dumps({'check_id':check})}}]}
    provider=Provider();job,_=submission(h,p,t,ai=True)
    Worker(h.engine,h.settings,provider).once()
    saved=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert state['requests']==1 and provider.count==1
    assert saved['report']['baseline']['findings']
    assert saved['target_calls']==saved['model_calls']==1
    assert saved['report']['investigation']['followups'][0]['status']=='unverified'


def test_bounded_attempts_and_heartbeat_fence(harness):
    h=harness;uid,p,t=h.create();job,_=submission(h,p,t);q=Queue(h.engine,replace(h.settings,max_attempts=1))
    attempt=q.claim();assert q.heartbeat(job,attempt['lease_token'])
    expire(h,job)
    with pytest.raises(store.Stopped):q.heartbeat(job,attempt['lease_token'])
    assert q.claim() is None
    assert h.client.get('/v2/jobs/'+job,headers=h.headers()).json()['state']=='failed'


def test_model_quota_precedes_dispatch_and_survives_retry(harness,monkeypatch):
    h=harness;uid,p,t=h.create();fake_target(monkeypatch)
    settings=replace(h.settings,models_per_day=1)
    class Provider:
        count=0
        def complete(self,*args):self.count+=1;raise TimeoutError('SECRET')
    provider=Provider()
    job,_=submission(h,p,t,ai=True);Worker(h.engine,settings,provider).once()
    with h.engine.begin() as conn:second=store.submit(conn,settings,uid,p,t,{'target_url':'https://fixture.example/','ai':True,'browser':False,'session_cookies':[]},'next')['id']
    Worker(h.engine,settings,provider).once()
    assert provider.count==1
    data=h.client.get('/v2/jobs/'+second,headers=h.headers()).json()
    assert data['model_calls']==0 and data['report']['baseline']['findings']


def test_redirect_after_verification_is_never_followed(harness,monkeypatch):
    import httpcore
    h=harness;uid,p,t=h.create();requests=[]
    class Response:
        status=302
        headers=[(b'location',b'http://127.0.0.1/SECRET'),(b'content-type',b'text/html')]
        def close(self):pass
        @property
        def stream(self):pytest.fail('Must not read body')
    def response(pool,request):requests.append(request);return Response()
    monkeypatch.setattr(httpcore.ConnectionPool,'handle_request',response)
    job,_=submission(h,p,t);Worker(h.engine,h.settings).once()
    saved=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert len(requests)==1 and saved['report']['baseline']['status']=='unverified'
    assert 'SECRET' not in json.dumps(saved)


def test_database_rejects_cross_owner_links_and_baseline_overwrite(harness,monkeypatch):
    from sqlalchemy.exc import IntegrityError,DBAPIError
    h=harness;uid,p,t=h.create();other,other_project,other_target=h.create('bob')
    with pytest.raises(IntegrityError):
        with h.engine.begin() as conn:conn.execute(update(db.targets).where(db.targets.c.id==t).values(user_id=other))
    fake_target(monkeypatch);job,_=submission(h,p,t);Worker(h.engine,h.settings).once()
    with pytest.raises(DBAPIError):
        with h.engine.begin() as conn:conn.execute(update(db.jobs).where(db.jobs.c.id==job).values(report={}))


def test_readiness_requires_worker_heartbeat_and_metrics_are_owned(harness):
    h=harness;h.create()
    assert h.client.get('/health/live').status_code==200
    assert h.client.get('/health/ready').status_code==503
    with h.engine.begin() as conn:
        conn.execute(db.workers.insert().values(id=db.ident(),heartbeat_at=db.now(conn),active=0))
    assert h.client.get('/health/ready').status_code==200
    metrics=h.client.get('/v2/metrics',headers=h.headers()).json()
    assert metrics['workers_healthy']==1 and metrics['calls']==[]


def test_migration_matches_runtime_metadata(database):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    with database.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn),db.metadata)==[]


def test_real_worker_crash_preserves_dispatch_accounting(harness,tmp_path):
    import os,sys,subprocess
    from pathlib import Path
    h=harness;uid,p,t=h.create();job,_=submission(h,p,t,ai=True)
    marker=tmp_path/'dispatch'
    env={**os.environ,'PATCHPROOF_TEST_DISPATCH_MARKER':str(marker)}
    process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('crash_worker.py'))],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+15
        while not marker.exists() and time.monotonic()<deadline:
            assert process.poll() is None
            time.sleep(.05)
        assert marker.exists()
        process.kill();process.wait(timeout=5)
        expire(h,job);assert Queue(h.engine,h.settings).claim() is None
        saved=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
        assert saved['state']=='interrupted'
        assert saved['target_calls']==saved['model_calls']==1
        assert saved['report']['baseline']['findings']
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)


def test_migration_grants_runtime_role_without_ddl(database,settings,monkeypatch):
    from sqlalchemy.exc import DBAPIError
    from patchproof.hosted.migrate import upgrade
    role='pp_test_'+db.ident()[:12]
    with database.begin() as conn:conn.execute(text(f'CREATE ROLE {role} LOGIN'))
    runtime=None
    try:
        monkeypatch.setenv('PATCHPROOF_RUNTIME_ROLE',role)
        upgrade(settings.database_url)
        runtime=db.engine(database.url.set(username=role).render_as_string(hide_password=False))
        from patchproof.hosted.api import ready
        ready(runtime)
        with runtime.begin() as conn:
            conn.execute(db.users.insert().values(id=db.ident(),issuer='https://test.example',subject='role-test',created_at=db.now(conn)))
        with pytest.raises(DBAPIError):
            with runtime.begin() as conn:conn.execute(text('DROP TABLE workers'))
        with pytest.raises(DBAPIError):
            with runtime.begin() as conn:conn.execute(text('CREATE TABLE unauthorized (id integer)'))
    finally:
        if runtime:runtime.dispose()
        with database.begin() as conn:
            conn.execute(text(f'DROP OWNED BY {role}'));conn.execute(text(f'DROP ROLE {role}'))


def test_reported_model_usage_and_request_correlation(harness,monkeypatch):
    h=harness;uid,p,t=h.create();fake_target(monkeypatch)
    class Provider:
        last_usage={'prompt_tokens':17,'completion_tokens':8,'SECRET':'not retained'}
        def complete(self,*args):return {'content':'invalid explanation'}
    job,_=submission(h,p,t,ai=True);Worker(h.engine,h.settings,Provider()).once()
    data=h.client.get('/v2/jobs/'+job,headers=h.headers()).json()
    assert len(data['request_id'])==32
    metrics=h.client.get('/v2/metrics',headers=h.headers()).json()
    assert metrics['reported_prompt_tokens']==17 and metrics['reported_completion_tokens']==8
    assert metrics['reserved_output_token_cap']==2048
    with h.engine.connect() as conn:
        rows=[dict(r) for r in conn.execute(select(db.calls)).mappings()]
        assert 'SECRET' not in json.dumps(rows)


def test_initial_migration_refuses_existing_unversioned_tables(database,settings):
    from patchproof.hosted.migrate import upgrade
    with database.begin() as conn:conn.execute(text('DROP TABLE alembic_version'))
    with pytest.raises(RuntimeError,match='empty dedicated database'):
        upgrade(settings.database_url)
    with database.connect() as conn:assert conn.scalar(select(func.count()).select_from(db.jobs))==0


def test_forged_tokens_and_foreign_target_mutations(harness):
    import jwt
    h=harness;uid,p,t=h.create();h.create('bob')
    forged=jwt.encode({'iss':h.settings.issuer,'aud':h.settings.audience,'sub':'alice','iat':int(time.time()),'exp':int(time.time())+600},'attacker'*8,algorithm='HS256')
    assert h.client.get('/v2/projects',headers={'Authorization':'Bearer '+forged}).status_code==401
    for operation in ('verify','revoke'):
        assert h.client.post(f'/v2/targets/{t}/{operation}',headers=h.headers('bob'),json={}).status_code==404
