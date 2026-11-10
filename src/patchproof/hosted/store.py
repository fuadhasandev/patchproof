import hashlib
import json
import secrets
import ipaddress
from urllib.parse import urlsplit
import dns.resolver
from sqlalchemy import select, update, func, and_, or_
from sqlalchemy.dialects.postgresql import insert
from . import db
from ..policy import validate_url

TERMINAL = ('completed','failed','interrupted','cancelled')
class Missing(Exception): pass
class Denied(Exception): pass
class Conflict(Exception): pass
class Limited(Exception): pass
class Stopped(Exception): pass


def owned(conn, table, resource_id, user_id, lock=False):
    query = select(table).where(table.c.id == resource_id, table.c.user_id == user_id)
    if lock: query = query.with_for_update()
    row = conn.execute(query).mappings().first()
    if row is None: raise Missing('Resource not found.')
    return dict(row)


def hostname(value):
    url = validate_url('https://' + value + '/')
    host = urlsplit(url).hostname
    if value != host or '.' not in host or ':' in value or '/' in value:
        raise ValueError('Use one exact DNS hostname.')
    try: ipaddress.ip_address(host)
    except ValueError: return host
    raise ValueError('Use a DNS hostname, not an address.')


def rate(conn, key, maximum, seconds):
    window = int(db.now(conn)) // seconds
    stmt = insert(db.limits).values(key=key, window=window, count=1)
    result = conn.execute(stmt.on_conflict_do_update(index_elements=['key','window'],
        set_={'count': db.limits.c.count + 1}, where=db.limits.c.count < maximum).returning(db.limits.c.count)).scalar()
    if result is None: raise Limited('Rate or usage limit reached.')


def authorize(conn, target_id, user_id, url, lock=False):
    target = owned(conn, db.targets, target_id, user_id, lock)
    if target['revoked'] or target['verified_until'] <= db.now(conn) or urlsplit(url).hostname != target['hostname']:
        raise Denied('Target verification required or expired.')
    return target


def challenge(conn, user_id, project_id, host, settings):
    owned(conn, db.projects, project_id, user_id)
    rate(conn, 'verify:' + user_id, settings.submissions_per_minute, 60)
    token = 'patchproof=' + secrets.token_urlsafe(32)
    ident = db.ident(); stamp = db.now(conn)
    conn.execute(insert(db.targets).values(id=ident, user_id=user_id, project_id=project_id, hostname=hostname(host),
        challenge_hash=hashlib.sha256(token.encode()).hexdigest(), challenge_expires=stamp + settings.challenge_seconds,
        verified_until=0, revoked=False, created_at=stamp).on_conflict_do_update(index_elements=['project_id','hostname'],
        set_={'challenge_hash': hashlib.sha256(token.encode()).hexdigest(), 'challenge_expires': stamp + settings.challenge_seconds,
              'verified_until': 0, 'revoked': False}))
    target = conn.execute(select(db.targets.c.id).where(db.targets.c.project_id == project_id, db.targets.c.hostname == host)).scalar_one()
    return {'id': target, 'record': '_patchproof.' + host, 'value': token, 'expires_at': stamp + settings.challenge_seconds}


def txt_records(record):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 5
    try:
        return [b''.join(answer.strings).decode('ascii') for answer in resolver.resolve(record, 'TXT', search=False)]
    except Exception:
        return []


def verify_target(engine, user_id, target_id, settings, resolver=txt_records):
    with engine.begin() as conn:
        rate(conn, 'verify:' + user_id, settings.submissions_per_minute, 60)
        target = owned(conn, db.targets, target_id, user_id)
        if target['revoked'] or target['challenge_expires'] <= db.now(conn): raise Denied('Challenge expired or revoked.')
    records = resolver('_patchproof.' + target['hostname'])
    match = any(secrets.compare_digest(hashlib.sha256(r.encode()).hexdigest(), target['challenge_hash'] or '') for r in records[:64])
    with engine.begin() as conn:
        current = owned(conn, db.targets, target_id, user_id, True)
        if current['revoked'] or current['challenge_hash'] != target['challenge_hash'] or current['challenge_expires'] <= db.now(conn) or not match:
            raise Denied('DNS challenge not verified.')
        until = db.now(conn) + settings.verification_seconds
        conn.execute(update(db.targets).where(db.targets.c.id == target_id).values(verified_until=until))
        return {'id': target_id, 'verified_until': until}


def submit(conn, settings, user_id, project_id, target_id, inputs, key, *, finding_id=None, request_id=None):
    if not key or len(key) > 128: raise ValueError('Idempotency-Key required (1–128 characters).')
    # User lock serializes idempotency lookup and insertion across API processes.
    conn.execute(select(db.users.c.id).where(db.users.c.id == user_id).with_for_update()).scalar_one()
    owned(conn, db.projects, project_id, user_id)
    target = owned(conn, db.targets, target_id, user_id)
    if target['project_id'] != project_id: raise Missing('Resource not found.')
    normalized = {'project_id': project_id, 'target_id': target_id, 'inputs': inputs, 'finding_id': finding_id}
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',',':')).encode()).hexdigest()
    existing = conn.execute(select(db.jobs).where(db.jobs.c.user_id == user_id, db.jobs.c.idempotency_key == key)).mappings().first()
    if existing:
        if existing['request_hash'] != digest: raise Conflict('Idempotency key already used for different inputs.')
        return {'id': existing['id'], 'state': existing['state']}
    authorize(conn, target_id, user_id, inputs['target_url'])
    rate(conn, 'submit:' + user_id, settings.submissions_per_minute, 60)
    count = conn.scalar(select(func.count()).select_from(db.jobs).where(db.jobs.c.user_id == user_id, db.jobs.c.state.in_(('queued','running'))))
    if count >= settings.pending_limit: raise Limited('Pending job limit reached.')
    job_id = db.ident(); stamp = db.now(conn)
    kind = 'recheck' if finding_id else 'scan'
    conn.execute(insert(db.jobs).values(id=job_id, user_id=user_id, project_id=project_id, target_id=target_id,
        kind=kind, state='queued', target_url=inputs['target_url'], inputs=inputs, original_finding_id=finding_id,
        request_id=request_id, idempotency_key=key, request_hash=digest, created_at=stamp, updated_at=stamp))
    table = db.rechecks if finding_id else db.scans
    values = dict(id=job_id, user_id=user_id, project_id=project_id, job_id=job_id)
    if finding_id: values['finding_id'] = finding_id
    conn.execute(insert(table).values(**values))
    return {'id': job_id, 'state': 'queued'}


def public_job(row):
    return {k: row[k] for k in ('id','kind','state','project_id','target_id','target_url','created_at','updated_at','finished_at',
            'original_finding_id','retry_of','attempts','progress','error','report','target_calls','model_calls','cancel_requested','request_id')}


def job_report(conn, job_id, user_id):
    row = owned(conn, db.jobs, job_id, user_id)
    result = public_job(row)
    result['findings'] = []
    for finding in conn.execute(select(db.findings).where(db.findings.c.job_id == job_id, db.findings.c.user_id == user_id).order_by(db.findings.c.ordinal)).mappings():
        latest = conn.execute(select(db.jobs).where(db.jobs.c.original_finding_id == finding['id'], db.jobs.c.user_id == user_id).order_by(db.jobs.c.seq.desc()).limit(1)).mappings().first()
        result['findings'].append({'id': finding['id'], **finding['data'], 'latest_recheck': public_job(latest) if latest else None})
    return result


def history(conn, user_id, *, project_id=None, finding_id=None, limit=20, before=None):
    query = select(db.jobs).where(db.jobs.c.user_id == user_id)
    if project_id:
        owned(conn, db.projects, project_id, user_id)
        query = query.where(db.jobs.c.project_id == project_id, db.jobs.c.kind == 'scan')
    if finding_id:
        owned(conn, db.findings, finding_id, user_id)
        query = query.where(db.jobs.c.original_finding_id == finding_id)
    if before:
        cursor = owned(conn, db.jobs, before, user_id)
        if (project_id and cursor['project_id'] != project_id) or (finding_id and cursor['original_finding_id'] != finding_id):
            raise Missing('Cursor not found.')
        query = query.where(db.jobs.c.seq < cursor['seq'])
    rows = conn.execute(query.order_by(db.jobs.c.seq.desc()).limit(limit+1)).mappings().all()
    return {'items': [public_job(r) for r in rows[:limit]], 'next_cursor': rows[limit-1]['id'] if len(rows)>limit else None}
