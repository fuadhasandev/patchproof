"""Authenticated v2 API. No target or model execution in this process."""
import json
import re
from contextlib import asynccontextmanager
from uuid import uuid4
from fastapi import FastAPI, Request, Depends, Query, HTTPException
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from pydantic import Field
from sqlalchemy import select, update, func, text
from sqlalchemy.dialects.postgresql import insert
from . import db, store
from .settings import Settings
from .auth import OIDC, AuthenticationError, user_id
from ..api import ScanInput, EmptyInput
from ..models import Model
from .._version import __version__


def ready(engine):
    with engine.connect() as conn:
        if conn.scalar(text('SHOW server_encoding')) != 'UTF8':
            raise RuntimeError('Hosted PostgreSQL requires UTF8 encoding.')
        if list(conn.execute(text('SELECT version_num FROM alembic_version')).scalars()) != ['0001_hosted']:
            raise RuntimeError('Database migrations required.')
        conn.execute(select(db.jobs.c.id).limit(1))


class ProjectInput(Model):
    name: str = Field(min_length=1, max_length=100, pattern=r'^[\w .-]+$')
class TargetInput(Model):
    hostname: str = Field(max_length=253)
class HostedScan(ScanInput):
    project_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    target_id: str = Field(pattern=r'^[a-f0-9]{32}$')


def create_app(settings=None, *, engine=None, authenticator=None, resolver=None):
    settings = settings or Settings.from_environment()
    engine = engine or db.engine(settings.database_url)
    auth = authenticator or OIDC(settings)
    @asynccontextmanager
    async def lifespan(app):
        ready(engine)
        yield
        engine.dispose()
    app = FastAPI(version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine = engine

    @app.middleware('http')
    async def boundary(request, call_next):
        request_id = uuid4().hex
        request.state.request_id = request_id
        try:
            if request.method not in ('GET','HEAD'):
                if request.headers.get('origin') != settings.origin:
                    return JSONResponse({'detail':'Unexpected request origin.','request_id':request_id},403)
                if request.headers.get('content-type','').split(';')[0] != 'application/json':
                    return JSONResponse({'detail':'JSON request required.','request_id':request_id},415)
            body = bytearray()
            async for chunk in request.stream():
                if len(body)+len(chunk)>8192:
                    return JSONResponse({'detail':'Request too large.','request_id':request_id},413)
                body.extend(chunk)
            request._body = bytes(body)
            response = await call_next(request)
        except Exception:
            response = JSONResponse({'detail':'Infrastructure unavailable.','request_id':request_id},503)
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Request-ID':request_id})
        # Never include URLs, subjects, request bodies, tokens or exception text.
        print(json.dumps({'event':'api_request','request_id':request_id,'status':response.status_code}), flush=True)
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        return JSONResponse({'detail':'Invalid request.','request_id':request.state.request_id},422)
    for kind, status in [(store.Missing,404),(store.Denied,403),(store.Conflict,409),(store.Limited,429),(AuthenticationError,401)]:
        def handler(code):
            async def respond(request, exc):
                return JSONResponse({'detail':str(exc),'request_id':request.state.request_id},code)
            return respond
        app.add_exception_handler(kind, handler(status))

    def identity(request: Request):
        header = request.headers.get('authorization','')
        if not header.startswith('Bearer ') or len(header)>16384: raise AuthenticationError('Authentication required.')
        subject = auth.verify(header[7:])
        with engine.begin() as conn: return user_id(conn, settings.issuer, subject)

    @app.get('/health/live')
    def live(): return {'status':'alive'}
    @app.get('/health/ready')
    def readiness():
        try:
            ready(engine)
            with engine.connect() as conn:
                healthy=conn.scalar(select(func.count()).select_from(db.workers).where(db.workers.c.heartbeat_at>db.now(conn)-settings.lease_seconds))
            if not healthy:return JSONResponse({'status':'worker_unavailable'},503)
        except Exception: return JSONResponse({'status':'not_ready'},503)
        return {'status':'ready'}
    @app.get('/v2/me')
    def me(uid=Depends(identity)):
        return {'id':uid, 'browser_available':False, 'browser_reason':'Hosted egress isolation is unavailable.'}
    @app.get('/v2/projects')
    def projects(limit: int=Query(20,ge=1,le=50), before: str | None=Query(None,max_length=32), uid=Depends(identity)):
        with engine.connect() as conn:
            query=select(db.projects).where(db.projects.c.user_id==uid)
            if before:
                store.owned(conn,db.projects,before,uid)
                query=query.where(db.projects.c.id<before)
            rows=conn.execute(query.order_by(db.projects.c.id.desc()).limit(limit+1)).mappings().all()
            return {'items':[dict(r) for r in rows[:limit]],'next_cursor':rows[limit-1]['id'] if len(rows)>limit else None}
    @app.post('/v2/projects',status_code=201)
    def create_project(body:ProjectInput,uid=Depends(identity)):
        with engine.begin() as conn:
            store.rate(conn,'project:'+uid,settings.submissions_per_minute,60)
            project_id=db.ident()
            conn.execute(insert(db.projects).values(id=project_id,user_id=uid,name=body.name,created_at=db.now(conn)))
            return {'id':project_id,'name':body.name}
    @app.get('/v2/projects/{project_id}/targets')
    def targets(project_id:str,limit:int=Query(20,ge=1,le=50),before:str|None=Query(None,max_length=32),uid=Depends(identity)):
        with engine.connect() as conn:
            store.owned(conn,db.projects,project_id,uid)
            query=select(db.targets).where(db.targets.c.project_id==project_id,db.targets.c.user_id==uid)
            if before:
                cursor=store.owned(conn,db.targets,before,uid)
                if cursor['project_id']!=project_id: raise store.Missing('Cursor not found.')
                query=query.where(db.targets.c.id<before)
            rows=conn.execute(query.order_by(db.targets.c.id.desc()).limit(limit+1)).mappings().all()
            return {'items':[{k:r[k] for k in ('id','hostname','verified_until','revoked')} for r in rows[:limit]],
                    'next_cursor':rows[limit-1]['id'] if len(rows)>limit else None}
    @app.post('/v2/projects/{project_id}/targets',status_code=201)
    def challenge(project_id:str,body:TargetInput,uid=Depends(identity)):
        try:
            with engine.begin() as conn: return store.challenge(conn,uid,project_id,body.hostname,settings)
        except ValueError: raise HTTPException(422,'Use one exact DNS hostname.') from None
    @app.post('/v2/targets/{target_id}/verify')
    def verify(target_id:str,body:EmptyInput,uid=Depends(identity)):
        return store.verify_target(engine,uid,target_id,settings,**({'resolver':resolver} if resolver else {}))
    @app.post('/v2/targets/{target_id}/revoke')
    def revoke(target_id:str,body:EmptyInput,uid=Depends(identity)):
        with engine.begin() as conn:
            store.owned(conn,db.targets,target_id,uid,True)
            conn.execute(update(db.targets).where(db.targets.c.id==target_id).values(revoked=True,verified_until=0,challenge_hash=None))
        return {'id':target_id,'revoked':True}
    @app.post('/v2/scans',status_code=202)
    def scan(body:HostedScan,request:Request,uid=Depends(identity)):
        try:
            with engine.begin() as conn:
                return store.submit(conn,settings,uid,body.project_id,body.target_id,
                    body.model_dump(exclude={'project_id','target_id'}),request.headers.get('idempotency-key',''),request_id=request.state.request_id)
        except ValueError: raise HTTPException(422,'Valid Idempotency-Key required.') from None
    @app.get('/v2/projects/{project_id}/scans')
    def history(project_id:str,limit:int=Query(20,ge=1,le=50),before:str|None=Query(None,max_length=32),uid=Depends(identity)):
        with engine.connect() as conn: return store.history(conn,uid,project_id=project_id,limit=limit,before=before)
    @app.get('/v2/jobs/{job_id}')
    def job(job_id:str,uid=Depends(identity)):
        with engine.connect() as conn: return store.job_report(conn,job_id,uid)
    @app.post('/v2/jobs/{job_id}/cancel')
    def cancel(job_id:str,body:EmptyInput,uid=Depends(identity)):
        with engine.begin() as conn:
            job=store.owned(conn,db.jobs,job_id,uid,True)
            if job['state'] not in store.TERMINAL:
                values={'cancel_requested':True,'updated_at':db.now(conn)}
                if job['state']=='queued': values.update(state='cancelled',progress='cancelled',finished_at=db.now(conn))
                conn.execute(update(db.jobs).where(db.jobs.c.id==job_id).values(**values))
        return {'id':job_id,'cancel_requested':job['cancel_requested'] if job['state'] in store.TERMINAL else True}
    @app.get('/v2/findings/{finding_id}/spec')
    def spec(finding_id:str,uid=Depends(identity)):
        with engine.connect() as conn:
            finding=store.owned(conn,db.findings,finding_id,uid)
            from ..service import validate_spec
            spec=validate_spec(finding['data']['spec'])
            return Response(spec.model_dump_json(indent=2)+'\n',media_type='application/json',headers={'Content-Disposition':'attachment; filename="patchproof-check.json"'})
    @app.post('/v2/findings/{finding_id}/rechecks',status_code=202)
    def recheck(finding_id:str,body:EmptyInput,request:Request,uid=Depends(identity)):
        with engine.begin() as conn:
            finding=store.owned(conn,db.findings,finding_id,uid)
            original=store.owned(conn,db.jobs,finding['job_id'],uid)
            try: return store.submit(conn,settings,uid,finding['project_id'],original['target_id'],finding['data']['spec'],request.headers.get('idempotency-key',''),finding_id=finding_id,request_id=request.state.request_id)
            except ValueError: raise HTTPException(422,'Valid Idempotency-Key required.') from None
    @app.get('/v2/findings/{finding_id}/rechecks')
    def timeline(finding_id:str,limit:int=Query(20,ge=1,le=50),before:str|None=Query(None,max_length=32),uid=Depends(identity)):
        with engine.connect() as conn: return store.history(conn,uid,finding_id=finding_id,limit=limit,before=before)
    @app.get('/v2/metrics')
    def metrics(uid=Depends(identity)):
        with engine.connect() as conn:
            states=conn.execute(select(db.jobs.c.state,func.count()).where(db.jobs.c.user_id==uid).group_by(db.jobs.c.state)).all()
            usage=conn.execute(select(db.calls.c.kind,db.calls.c.state,func.count()).where(db.calls.c.user_id==uid).group_by(db.calls.c.kind,db.calls.c.state)).all()
            return {'jobs':dict(states),'calls':[{'kind':r[0],'state':r[1],'count':r[2]} for r in usage],
                    'reported_prompt_tokens':conn.scalar(select(func.coalesce(func.sum(db.calls.c.usage['prompt_tokens'].as_integer()),0)).where(db.calls.c.user_id==uid)),
                    'reported_completion_tokens':conn.scalar(select(func.coalesce(func.sum(db.calls.c.usage['completion_tokens'].as_integer()),0)).where(db.calls.c.user_id==uid)),
                    'reserved_output_token_cap':conn.scalar(select(func.coalesce(func.sum(db.calls.c.output_token_limit),0)).where(db.calls.c.user_id==uid)),
                    'workers_healthy':conn.scalar(select(func.count()).select_from(db.workers).where(db.workers.c.heartbeat_at>db.now(conn)-settings.lease_seconds))}
    return app
