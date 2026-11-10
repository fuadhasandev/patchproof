import json
import os
import shutil
import subprocess
import pytest
from sqlalchemy import select,text
from patchproof.hosted import db,store
from patchproof.hosted.import_sqlite import import_database
from patchproof.storage import Store
from patchproof import service


def legacy_database(path,fixture_site):
    url,state=fixture_site
    local=Store(path)
    baseline=service.scan(url,allow_local=True)
    first=local.create(kind='scan',target=url,inputs={'target_url':url,'session_cookies':[],'ai':False,'browser':False})
    local.running(first);local.complete(first,{'baseline':baseline.model_dump(mode='json'),'investigation':None},baseline)
    finding=local.get(first)['findings'][0]
    state['csp']='present';spec=service.validate_spec(finding['spec'])
    result=service.execute(spec,allow_local=True)
    second=local.create(kind='recheck',target=url,inputs=spec.model_dump(),finding_id=finding['id'])
    local.running(second);local.complete(second,{'result':result.model_dump(mode='json')})
    local.close()
    return first,finding['id'],second


def test_atomic_import_preserves_ids_and_never_authorizes(harness,tmp_path,fixture_site):
    h=harness
    uid=h.client.get('/v2/me',headers=h.headers()).json()['id']
    p=h.client.post('/v2/projects',headers=h.headers(),json={'name':'Import'}).json()['id']
    source=tmp_path/'legacy.sqlite3';scan,finding,recheck=legacy_database(source,fixture_site)
    original=source.read_bytes()
    result=import_database(source,h.engine,uid,p)
    assert result=={'jobs':2,'findings':1,'applied':False}
    with h.engine.connect() as conn:assert conn.scalar(select(db.jobs.c.id)) is None
    import_database(source,h.engine,uid,p,apply=True)
    assert source.read_bytes()==original
    data=h.client.get('/v2/jobs/'+scan,headers=h.headers()).json()
    assert data['findings'][0]['id']==finding
    assert data['findings'][0]['latest_recheck']['id']==recheck
    assert data['findings'][0]['latest_recheck']['report']['result']['status']=='resolved'
    assert h.client.get(f'/v2/findings/{finding}/spec',headers=h.headers()).json()['schema_version']=='1'
    with h.engine.connect() as conn:
        target=conn.execute(select(db.targets)).mappings().one();assert target['revoked'] and target['verified_until']==0
    with pytest.raises(ValueError):import_database(source,h.engine,uid,p,apply=True)
    with h.engine.connect() as conn:assert len(conn.execute(select(db.jobs)).all())==2


def test_pg_backup_restore_preserves_history(harness,tmp_path,fixture_site):
    if not shutil.which('pg_dump') or not shutil.which('pg_restore'):pytest.fail('PostgreSQL client tools required for hosted acceptance.')
    h=harness;uid=h.client.get('/v2/me',headers=h.headers()).json()['id']
    p=h.client.post('/v2/projects',headers=h.headers(),json={'name':'Restore'}).json()['id']
    source=tmp_path/'legacy.sqlite3';scan,finding,recheck=legacy_database(source,fixture_site)
    import_database(source,h.engine,uid,p,apply=True)
    from sqlalchemy.engine import make_url
    url=make_url(h.settings.database_url)
    env={**os.environ,'PGHOST':url.host,'PGPORT':str(url.port or 5432),'PGUSER':url.username,'PGDATABASE':url.database,'LC_ALL':'C'}
    if url.password:env['PGPASSWORD']=url.password
    backup=tmp_path/'backup.dump'
    subprocess.run(['pg_dump','--format=custom','--file',str(backup)],env=env,check=True,capture_output=True)
    with h.engine.begin() as conn:conn.execute(text('DROP SCHEMA public CASCADE'));conn.execute(text('CREATE SCHEMA public'))
    subprocess.run(['pg_restore','--exit-on-error','--no-owner','--dbname',url.database,str(backup)],env=env,check=True,capture_output=True)
    with h.engine.connect() as conn:
        saved=store.job_report(conn,scan,uid)
        assert saved['findings'][0]['id']==finding
        assert saved['findings'][0]['latest_recheck']['id']==recheck
        assert saved['findings'][0]['latest_recheck']['report']['result']['status']=='resolved'
