"""Explicit ownership and a PostgreSQL-only hosted queue; no implicit schema creation."""
from uuid import uuid4
from sqlalchemy import (MetaData, Table, Column, String, Text, Float, Integer, BigInteger,
                        Boolean, JSON, ForeignKey, UniqueConstraint, CheckConstraint,
                        Index, Identity, create_engine, select, func)

metadata = MetaData()
def ident(): return uuid4().hex
def idcol(): return Column('id', String(32), primary_key=True)
def owner(): return Column('user_id', String(32), ForeignKey('users.id'), nullable=False, index=True)
def project(): return Column('project_id', String(32), ForeignKey('projects.id'), nullable=False, index=True)
users = Table('users', metadata, idcol(), Column('issuer', Text, nullable=False), Column('subject', String(255), nullable=False),
              Column('created_at', Float, nullable=False), UniqueConstraint('issuer','subject'))
projects = Table('projects', metadata, idcol(), owner(), Column('name', String(100), nullable=False), Column('created_at', Float, nullable=False))
targets = Table('targets', metadata, idcol(), owner(), project(), Column('hostname', String(253), nullable=False),
    Column('challenge_hash', String(64)), Column('challenge_expires', Float, nullable=False),
    Column('verified_until', Float, nullable=False, default=0), Column('revoked', Boolean, nullable=False, default=False),
    Column('created_at', Float, nullable=False), UniqueConstraint('project_id','hostname'))
jobs = Table('jobs', metadata, idcol(), Column('seq', BigInteger, Identity(), unique=True, nullable=False), owner(), project(),
    Column('target_id', String(32), ForeignKey('targets.id'), nullable=False),
    Column('kind', String(16), nullable=False), Column('state', String(16), nullable=False),
    Column('target_url', Text, nullable=False), Column('inputs', JSON, nullable=False),
    Column('original_finding_id', String(32)), Column('retry_of', String(32), ForeignKey('jobs.id')),
    Column('request_id', String(32)), Column('idempotency_key', String(128), nullable=False), Column('request_hash', String(64), nullable=False),
    Column('created_at', Float, nullable=False), Column('updated_at', Float, nullable=False), Column('finished_at', Float),
    Column('attempts', Integer, nullable=False, default=0), Column('lease_token', String(32)), Column('lease_until', Float),
    Column('available_at', Float, nullable=False, default=0), Column('cancel_requested', Boolean, nullable=False, default=False),
    Column('target_calls', Integer, nullable=False, default=0), Column('model_calls', Integer, nullable=False, default=0),
    Column('baseline', JSON), Column('report', JSON), Column('progress', String(40), nullable=False, default='queued'),
    Column('error', String(200)), UniqueConstraint('user_id','idempotency_key'),
    CheckConstraint("kind IN ('scan','recheck')"),
    CheckConstraint("state IN ('queued','running','completed','failed','interrupted','cancelled')"),
    CheckConstraint('attempts >= 0 AND target_calls >= 0 AND model_calls >= 0'))
scans = Table('scans', metadata, idcol(), owner(), project(), Column('job_id', String(32), ForeignKey('jobs.id'), nullable=False, unique=True))
findings = Table('findings', metadata, idcol(), owner(), project(), Column('job_id', String(32), ForeignKey('jobs.id'), nullable=False, index=True),
    Column('ordinal', Integer, nullable=False), Column('data', JSON, nullable=False), UniqueConstraint('job_id','ordinal'))
checks = Table('checkspecs', metadata, idcol(), owner(), project(), Column('finding_id', String(32), ForeignKey('findings.id'), nullable=False, unique=True),
               Column('spec', JSON, nullable=False))
rechecks = Table('rechecks', metadata, idcol(), owner(), project(), Column('finding_id', String(32), ForeignKey('findings.id'), nullable=False, index=True),
    Column('job_id', String(32), ForeignKey('jobs.id'), nullable=False, unique=True))
# The deferred FK accommodates importing legacy jobs/findings in one transaction.
from sqlalchemy import ForeignKeyConstraint
jobs.append_constraint(ForeignKeyConstraint(['original_finding_id'], ['findings.id'], name='jobs_original_finding_fk', use_alter=True, deferrable=True, initially='DEFERRED'))
calls = Table('external_calls', metadata, idcol(), Column('job_id', String(32), ForeignKey('jobs.id'), nullable=False, index=True), owner(),
    Column('kind', String(10), nullable=False), Column('attempt', Integer, nullable=False), Column('lease_token', String(32), nullable=False),
    Column('state', String(16), nullable=False), Column('created_at', Float, nullable=False), Column('finished_at', Float),
    Column('output_token_limit', Integer, nullable=False, default=0), Column('usage', JSON),
    CheckConstraint("kind IN ('target','model')"), CheckConstraint("state IN ('reserved','completed','uncertain')"))
limits = Table('rate_limits', metadata, Column('key', String(128), primary_key=True), Column('window', BigInteger, primary_key=True), Column('count', Integer, nullable=False))
workers = Table('workers', metadata, idcol(), Column('heartbeat_at', Float, nullable=False), Column('active', Integer, nullable=False))
Index('jobs_claim', jobs.c.state, jobs.c.available_at, jobs.c.seq)
Index('jobs_history', jobs.c.user_id, jobs.c.project_id, jobs.c.seq)
Index('recheck_history', jobs.c.original_finding_id, jobs.c.seq)

# Composite keys prevent owner/project mismatches even in maintenance/import code.
for table, columns in ((projects, ('id','user_id')), (targets, ('id','project_id','user_id')),
                       (jobs, ('id','project_id','user_id')), (findings, ('id','project_id','user_id'))):
    table.append_constraint(UniqueConstraint(*columns))
for table in (targets, jobs, scans, findings, checks, rechecks):
    table.append_constraint(ForeignKeyConstraint(['project_id','user_id'], ['projects.id','projects.user_id']))
jobs.append_constraint(ForeignKeyConstraint(['target_id','project_id','user_id'], ['targets.id','targets.project_id','targets.user_id']))
for table in (scans,findings,rechecks):
    table.append_constraint(ForeignKeyConstraint(['job_id','project_id','user_id'], ['jobs.id','jobs.project_id','jobs.user_id']))
for table in (checks,rechecks):
    table.append_constraint(ForeignKeyConstraint(['finding_id','project_id','user_id'], ['findings.id','findings.project_id','findings.user_id']))
jobs.append_constraint(ForeignKeyConstraint(['original_finding_id','project_id','user_id'], ['findings.id','findings.project_id','findings.user_id'],
    name='jobs_owned_original_finding_fk', use_alter=True, deferrable=True, initially='DEFERRED'))


def engine(url):
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5,
                         connect_args={'connect_timeout': 5, 'options': '-c statement_timeout=10000 -c lock_timeout=5000'}, hide_parameters=True)


def now(conn):
    return float(conn.scalar(select(func.extract('epoch', func.clock_timestamp()))))
