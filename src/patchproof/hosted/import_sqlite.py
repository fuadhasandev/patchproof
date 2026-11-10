"""Offline, atomic, no-overwrite import of a stopped local schema-1 database."""
import argparse
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from . import db, store
from ..api import ScanInput
from ..models import Finding, ScanResult, Result
from ..investigation import Investigation
from ..service import validate_spec


def validated_report(raw, kind):
    if raw is None: return None
    data=json.loads(raw)
    if kind=='recheck':
        if set(data)!={'result'}: raise ValueError('Invalid saved recheck report.')
        return {'result':Result.model_validate_json(json.dumps(data['result'])).model_dump(mode='json')}
    if set(data)!={'baseline','investigation'}: raise ValueError('Invalid saved scan report.')
    return {'baseline':ScanResult.model_validate_json(json.dumps(data['baseline'])).model_dump(mode='json'),
            'investigation':Investigation.model_validate_json(json.dumps(data['investigation'])).model_dump(mode='json') if data['investigation'] else None}


def import_database(source, engine, user_id, project_id, *, apply=False):
    source=Path(source).resolve()
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as legacy:
        legacy.row_factory=sqlite3.Row
        legacy.execute('BEGIN')
        if legacy.execute('PRAGMA user_version').fetchone()[0]!=1 or legacy.execute('PRAGMA quick_check').fetchone()[0]!='ok' or legacy.execute('PRAGMA foreign_key_check').fetchall():
            raise ValueError('Invalid or unsupported local database.')
        jobs=[dict(r) for r in legacy.execute('SELECT * FROM jobs ORDER BY seq')]
        findings=[dict(r) for r in legacy.execute('SELECT * FROM findings ORDER BY rowid')]
    import re
    for row in [*jobs,*findings]:
        if not re.fullmatch('[a-f0-9]{32}',row['id']): raise ValueError('Invalid legacy ID.')
    for job in jobs:
        if job['state'] not in (*store.TERMINAL,'queued','running') or job['kind'] not in ('scan','recheck'):
            raise ValueError('Invalid legacy state.')
        job['inputs']=ScanInput.model_validate_json(job['inputs_json']).model_dump(mode='json') if job['kind']=='scan' else validate_spec(json.loads(job['inputs_json'])).model_dump(mode='json')
        if job['inputs']['target_url']!=job['target_url']: raise ValueError('Conflicting legacy target.')
        job['baseline']=ScanResult.model_validate_json(job['baseline_json']).model_dump(mode='json') if job['baseline_json'] else None
        job['report']=validated_report(job['report_json'],job['kind'])
    for finding in findings:
        finding['data']=Finding.model_validate_json(finding['data_json']).model_dump(mode='json')
        validate_spec(finding['data']['spec'])
    indexed={j['id']:j for j in jobs}
    finding_index={f['id']:f for f in findings}
    for finding in findings:
        parent=indexed.get(finding['job_id'])
        if not parent or parent['kind']!='scan' or parent['target_url']!=finding['data']['spec']['target_url']:
            raise ValueError('Inconsistent finding ownership or target.')
    for job in jobs:
        if job['retry_of'] and job['retry_of'] not in indexed: raise ValueError('Missing retry parent.')
        if job['kind']=='recheck':
            parent=finding_index.get(job['original_finding_id'])
            if not parent or parent['data']['spec']!=job['inputs']: raise ValueError('Inconsistent recheck lineage.')
    with engine.begin() as conn:
        store.owned(conn,db.projects,project_id,user_id,True)
        # Serialize imports and submissions for this owner. A collision aborts the
        # complete transaction, even if the source overlaps a different owner.
        conn.execute(select(db.users.c.id).where(db.users.c.id==user_id).with_for_update()).scalar_one()
        job_ids=[j['id'] for j in jobs]; finding_ids=[f['id'] for f in findings]
        if conn.scalar(select(db.jobs.c.id).where(db.jobs.c.id.in_(job_ids)).limit(1)) or conn.scalar(select(db.findings.c.id).where(db.findings.c.id.in_(finding_ids)).limit(1)):
            raise ValueError('Import overlaps existing IDs; nothing was overwritten.')
        hosts={urlsplit(j['target_url']).hostname for j in jobs}
        if conn.scalar(select(db.targets.c.id).where(db.targets.c.project_id==project_id,db.targets.c.hostname.in_(hosts)).limit(1)):
            raise ValueError('Import requires a project without overlapping targets.')
        summary={'jobs':len(jobs),'findings':len(findings),'applied':apply}
        if not apply: return summary
        target_ids={}
        for job in jobs:
            host=urlsplit(job['target_url']).hostname
            if host not in target_ids:
                existing=conn.execute(select(db.targets).where(db.targets.c.project_id==project_id,db.targets.c.hostname==host)).mappings().first()
                if existing: raise ValueError('Import requires a project without overlapping targets.')
                target_ids[host]=db.ident()
                conn.execute(insert(db.targets).values(id=target_ids[host],user_id=user_id,project_id=project_id,hostname=host,
                    challenge_expires=0,verified_until=0,revoked=True,created_at=db.now(conn)))
            state=job['state'] if job['state'] in store.TERMINAL else 'interrupted'
            conn.execute(insert(db.jobs).values(id=job['id'],user_id=user_id,project_id=project_id,target_id=target_ids[host],
                kind=job['kind'],state=state,target_url=job['target_url'],inputs=job['inputs'],original_finding_id=job['original_finding_id'],
                retry_of=job['retry_of'],idempotency_key='import:'+job['id'],request_hash='imported',created_at=job['created_at'],updated_at=job['updated_at'],
                finished_at=job['finished_at'] or db.now(conn),baseline=job['baseline'],report=job['report'],progress=state,
                error='Imported unfinished job; not resumed.' if state=='interrupted' else ('Imported failed job.' if state=='failed' else None)))
            if job['kind']=='scan':
                conn.execute(insert(db.scans).values(id=job['id'],job_id=job['id'],user_id=user_id,project_id=project_id))
        ordinals={}
        for finding in findings:
            job_id=finding['job_id']; ordinal=ordinals.get(job_id,0); ordinals[job_id]=ordinal+1
            conn.execute(insert(db.findings).values(id=finding['id'],job_id=job_id,ordinal=ordinal,data=finding['data'],user_id=user_id,project_id=project_id))
            conn.execute(insert(db.checks).values(id=finding['id'],finding_id=finding['id'],spec=finding['data']['spec'],user_id=user_id,project_id=project_id))
        for job in jobs:
            if job['kind']=='recheck':
                conn.execute(insert(db.rechecks).values(id=job['id'],job_id=job['id'],finding_id=job['original_finding_id'],user_id=user_id,project_id=project_id))
        return summary


def main():
    import os
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source');parser.add_argument('--user-id',required=True);parser.add_argument('--project-id',required=True)
    parser.add_argument('--apply',action='store_true',help='Without this flag, validate only.')
    args=parser.parse_args()
    try:
        print(json.dumps(import_database(args.source,db.engine(os.environ['PATCHPROOF_DATABASE_URL']),args.user_id,args.project_id,apply=args.apply)))
    except Exception:
        parser.exit(2,'Import rejected. Check source integrity, ownership, schema and overlapping IDs. No changes committed.\n')

if __name__=='__main__': main()
