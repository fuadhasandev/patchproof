"""Transactional claims, fencing, request accounting and conservative recovery."""
from sqlalchemy import select, update, func
from sqlalchemy.dialects.postgresql import insert
from . import db
from .store import Stopped, Denied, Limited, authorize, rate

class Queue:
    def __init__(self, engine, settings):
        self.engine, self.settings = engine, settings

    def _current(self, conn, job_id, token):
        row = conn.execute(select(db.jobs).where(db.jobs.c.id == job_id).with_for_update()).mappings().first()
        if not row or row['state'] != 'running' or row['lease_token'] != token or row['lease_until'] <= db.now(conn):
            raise Stopped('Lease no longer current.')
        return row

    def recover(self, conn):
        stamp = db.now(conn)
        expired = conn.execute(select(db.jobs).where(db.jobs.c.state == 'running', db.jobs.c.lease_until <= stamp)
            .order_by(db.jobs.c.seq).limit(100).with_for_update(skip_locked=True)).mappings().all()
        for job in expired:
            # A dispatched model call may have been billed even when no result was
            # checkpointed. Never automatically repeat an AI investigation.
            if job['cancel_requested']:
                state, error = 'cancelled', 'Cancelled; any saved baseline is retained.'
            elif job['model_calls']:
                state, error = 'interrupted', 'Model call outcome may be uncertain; automatic replay disabled.'
            elif job['attempts'] >= self.settings.max_attempts or job['target_calls'] >= self.settings.target_limit:
                state, error = 'failed', 'Execution budget exhausted; any saved baseline is retained.'
            else:
                state, error = 'queued', 'Worker lease expired; retry preserves consumed budgets.'
            conn.execute(update(db.calls).where(db.calls.c.job_id == job['id'], db.calls.c.state == 'reserved')
                         .values(state='uncertain', finished_at=stamp))
            conn.execute(update(db.jobs).where(db.jobs.c.id == job['id']).values(state=state, error=error,
                lease_token=None, lease_until=None, updated_at=stamp, available_at=stamp + min(30,2**job['attempts']),
                finished_at=stamp if state != 'queued' else None, progress=state))

    def claim(self):
        with self.engine.begin() as conn:
            self.recover(conn)
            row = conn.execute(select(db.jobs).where(db.jobs.c.state == 'queued', db.jobs.c.available_at <= db.now(conn))
                .order_by(db.jobs.c.seq).limit(1).with_for_update(skip_locked=True)).mappings().first()
            if not row: return None
            token = db.ident(); stamp = db.now(conn)
            if row['attempts'] >= self.settings.max_attempts:
                conn.execute(update(db.jobs).where(db.jobs.c.id == row['id']).values(state='failed',progress='unverified',
                    error='Execution attempt budget exhausted.',finished_at=stamp,updated_at=stamp))
                return None
            try:
                authorize(conn, row['target_id'], row['user_id'], row['target_url'])
            except (Denied,):
                conn.execute(update(db.jobs).where(db.jobs.c.id == row['id']).values(state='failed', progress='unverified',
                    error='Target verification required or expired.', finished_at=stamp, updated_at=stamp))
                return None
            conn.execute(update(db.jobs).where(db.jobs.c.id == row['id']).values(state='running', attempts=row['attempts']+1,
                lease_token=token, lease_until=stamp+self.settings.lease_seconds, updated_at=stamp, progress='starting', error=None))
            return {**row, 'attempts': row['attempts']+1, 'lease_token': token}

    def heartbeat(self, job_id, token):
        with self.engine.begin() as conn:
            job = self._current(conn, job_id, token)
            stamp = db.now(conn)
            conn.execute(update(db.jobs).where(db.jobs.c.id == job_id).values(lease_until=stamp+self.settings.lease_seconds, updated_at=stamp))
            return not job['cancel_requested']

    def reserve(self, job_id, token, kind, url):
        with self.engine.begin() as conn:
            job = self._current(conn, job_id, token)
            if job['cancel_requested']: raise Stopped('Cancelled.')
            authorize(conn, job['target_id'], job['user_id'], url, lock=True)
            column, maximum = ('target_calls',self.settings.target_limit) if kind == 'target' else ('model_calls',self.settings.model_limit)
            if job[column] >= maximum: raise Limited('Execution budget exhausted.')
            if kind == 'target':
                rate(conn, 'target-user:' + job['user_id'], self.settings.targets_per_minute, 60)
                # Host-wide bucket is shared even across independently verified users.
                from urllib.parse import urlsplit
                import hashlib
                hostkey = hashlib.sha256(urlsplit(url).hostname.encode()).hexdigest()
                rate(conn, 'target-host:' + hostkey, self.settings.targets_per_minute, 60)
            else:
                rate(conn, 'model:' + job['user_id'], self.settings.models_per_day, 86400)
            stamp = db.now(conn); call_id = db.ident()
            conn.execute(insert(db.calls).values(id=call_id, job_id=job_id, user_id=job['user_id'], kind=kind,
                attempt=job['attempts'], lease_token=token, state='reserved', created_at=stamp,
                output_token_limit=self.settings.model_tokens if kind == 'model' else 0))
            conn.execute(update(db.jobs).where(db.jobs.c.id == job_id).values(**{column: job[column]+1}, updated_at=stamp, progress=kind))
            return call_id

    def call_done(self, job_id, token, call_id, uncertain=False, usage=None):
        with self.engine.begin() as conn:
            self._current(conn, job_id, token)
            conn.execute(update(db.calls).where(db.calls.c.id == call_id, db.calls.c.lease_token == token, db.calls.c.state == 'reserved')
                         .values(state='uncertain' if uncertain else 'completed', finished_at=db.now(conn),
                                 usage={k:v for k,v in (usage or {}).items() if k in ('prompt_tokens','completion_tokens') and type(v) is int and 0 <= v <= 1000000000}))

    def checkpoint(self, job_id, token, baseline):
        with self.engine.begin() as conn:
            job = self._current(conn, job_id, token)
            encoded = baseline.model_dump(mode='json')
            if job['baseline'] is not None:
                if job['baseline'] != encoded: raise Stopped('Original baseline is immutable.')
                return
            conn.execute(update(db.jobs).where(db.jobs.c.id == job_id).values(baseline=encoded,
                report={'baseline': encoded, 'investigation': None}, progress='baseline_saved', updated_at=db.now(conn)))
            for ordinal, finding in enumerate(baseline.findings):
                finding_id = db.ident()
                values = dict(user_id=job['user_id'], project_id=job['project_id'])
                conn.execute(insert(db.findings).values(id=finding_id, job_id=job_id, ordinal=ordinal, data=finding.model_dump(mode='json'), **values))
                conn.execute(insert(db.checks).values(id=finding_id, finding_id=finding_id, spec=finding.spec.model_dump(mode='json'), **values))

    def finish(self, job_id, token, report=None, error=None):
        with self.engine.begin() as conn:
            job = self._current(conn, job_id, token)
            stamp = db.now(conn)
            cancelled = job['cancel_requested']
            state = 'cancelled' if cancelled else 'failed' if error else 'completed'
            changes = dict(state=state, progress=state, updated_at=stamp, finished_at=stamp,
                lease_token=None, lease_until=None, error='Cancelled; saved baseline retained.' if cancelled else error)
            if report is not None and not cancelled: changes['report'] = report
            conn.execute(update(db.jobs).where(db.jobs.c.id == job_id).values(**changes))
            conn.execute(update(db.calls).where(db.calls.c.job_id == job_id, db.calls.c.state == 'reserved').values(state='uncertain', finished_at=stamp))
