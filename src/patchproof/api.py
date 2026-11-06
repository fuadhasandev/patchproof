"""Loopback-only HTTP application around the existing scan and replay services."""
import asyncio
import copy
import hmac
import ipaddress
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import Field, field_validator
from . import service
from .investigation import investigate
from .models import Model
from .policy import validate_url
from .cookies import validate_cookie_name


@dataclass(frozen=True)
class Settings:
    token: str = field(repr=False)
    fixture_origin: str | None = None
    workers: int = 2
    pending_limit: int = 8
    store_limit: int = 64
    ttl: float = 1800

    def __post_init__(self):
        if len(self.token) < 32:
            raise ValueError('Set PATCHPROOF_API_TOKEN to at least 32 characters.')
        if self.fixture_origin:
            value = validate_url(self.fixture_origin)
            parts = urlsplit(value)
            if parts.path not in ('', '/') or not ipaddress.ip_address(parts.hostname).is_loopback:
                raise ValueError('Fixture origin must use a literal loopback IP and no path.')
            object.__setattr__(self, 'fixture_origin', origin(value))
        if min(self.workers, self.pending_limit, self.store_limit, self.ttl) <= 0:
            raise ValueError('Job limits must be positive.')

    def allow_local(self, target):
        return self.fixture_origin is not None and origin(target) == self.fixture_origin


def origin(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'


class ScanInput(Model):
    target_url: str = Field(max_length=2048)
    session_cookies: list[str] = Field(default_factory=list, max_length=16)
    ai: bool = False

    @field_validator('target_url')
    @classmethod
    def target(cls, value):
        return validate_url(value)

    @field_validator('session_cookies')
    @classmethod
    def cookies(cls, values):
        return list(dict.fromkeys(validate_cookie_name(v) for v in values))


class EmptyInput(Model):
    pass


class Jobs:
    def __init__(self, settings):
        self.settings = settings
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(settings.pending_limit)
        self.pool = ThreadPoolExecutor(max_workers=settings.workers, thread_name_prefix='patchproof')
        self.jobs = {}
        self.closed = False

    def purge(self):
        with self.lock:
            now = time.monotonic()
            for job_id in list(self.jobs):
                job = self.jobs[job_id]
                if job['state'] in ('completed', 'failed') and now - job['_finished'] >= self.settings.ttl:
                    del self.jobs[job_id]

    def submit(self, operation, *, kind='scan', finding_id=None):
        with self.lock:
            self.purge()
            if self.closed or len(self.jobs) >= self.settings.store_limit or not self.slots.acquire(blocking=False):
                raise HTTPException(429, 'Local job capacity reached. Wait for jobs to finish or expire.')
            job_id = uuid4().hex
            self.jobs[job_id] = dict(id=job_id, kind=kind, state='queued', created_at=time.time(),
                original_finding_id=finding_id, report=None, findings=[], error=None, _finished=None)
            try:
                self.pool.submit(self._run, job_id, operation)
            except Exception:
                del self.jobs[job_id]
                self.slots.release()
                raise HTTPException(503, 'Job runner unavailable.') from None
            return {'id': job_id, 'state': 'queued'}

    def _run(self, job_id, operation):
        with self.lock:
            self.jobs[job_id]['state'] = 'running'
        try:
            report, findings = operation()
            entries = [dict(id=uuid4().hex, **f.model_dump(mode='json')) for f in findings]
            with self.lock:
                self.jobs[job_id].update(state='completed', report=report, findings=entries)
        except Exception:
            with self.lock:
                self.jobs[job_id].update(state='failed', error='Job failed; no evaluable report is available.')
        finally:
            with self.lock:
                self.jobs[job_id]['_finished'] = time.monotonic()
            self.slots.release()

    def get(self, job_id):
        with self.lock:
            self.purge()
            if job_id not in self.jobs:
                raise HTTPException(404, 'Job not found or expired. API restarts clear history.')
            job = copy.deepcopy(self.jobs[job_id])
            job.pop('_finished')
            for finding in job['findings']:
                matches = [j for j in self.jobs.values() if j['original_finding_id'] == finding['id']]
                latest = max(matches, key=lambda j: j['created_at']) if matches else None
                finding['latest_recheck'] = ({k: copy.deepcopy(latest[k]) for k in
                    ('id', 'state', 'report', 'error')} if latest else None)
            return job

    def finding(self, finding_id):
        with self.lock:
            self.purge()
            for job in self.jobs.values():
                for finding in job['findings']:
                    if finding['id'] == finding_id:
                        return copy.deepcopy(finding)
        raise HTTPException(404, 'Finding not found or expired.')

    def close(self):
        self.closed = True
        self.pool.shutdown(wait=True, cancel_futures=False)


def create_app(settings: Settings | None = None, *, provider=None):
    settings = settings or Settings(token=os.environ.get('PATCHPROOF_API_TOKEN', ''),
                                   fixture_origin=os.environ.get('PATCHPROOF_FIXTURE_ORIGIN') or None)
    jobs = Jobs(settings)

    @asynccontextmanager
    async def lifespan(app):
        async def cleanup():
            while True:
                await asyncio.sleep(30)
                jobs.purge()
        task = asyncio.create_task(cleanup())
        yield
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.to_thread(jobs.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.jobs = jobs

    @app.middleware('http')
    async def boundary(request: Request, call_next):
        if request.headers.get('host') != '127.0.0.1:8000':
            return JSONResponse({'detail': 'Unexpected API host.'}, 403)
        credential = request.headers.get('authorization', '')
        if not hmac.compare_digest(credential.encode(), ('Bearer ' + settings.token).encode()):
            return JSONResponse({'detail': 'Local API authentication required.'}, 401)
        if request.method not in ('GET', 'HEAD'):
            if request.headers.get('origin') != 'http://localhost:3000':
                return JSONResponse({'detail': 'Unexpected request origin.'}, 403)
            if request.headers.get('content-type', '').split(';')[0] != 'application/json':
                return JSONResponse({'detail': 'JSON request required.'}, 415)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 8192:
                    return JSONResponse({'detail': 'Request too large.'}, 413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        # Pydantic errors include the submitted values by default: do not return them.
        return JSONResponse({'detail': 'Invalid request. Use an HTTP(S) target without query or credentials and valid cookie names.'}, 422)

    @app.get('/v1/capabilities')
    def capabilities():
        return {'investigation': True, 'ai_configured': bool(os.environ.get('OPENROUTER_API_KEY') and os.environ.get('OPENROUTER_MODEL')),
                'fixture_origin': settings.fixture_origin, 'history_ttl_seconds': settings.ttl,
                'workers': settings.workers, 'pending_limit': settings.pending_limit, 'store_limit': settings.store_limit}

    @app.post('/v1/scans', status_code=202)
    def scan(body: ScanInput):
        def operation():
            options = dict(allow_local=settings.allow_local(body.target_url), session_cookies=body.session_cookies)
            if body.ai:
                result = investigate(body.target_url, provider=provider, **options)
                return {'baseline': result.baseline.model_dump(mode='json'),
                        'investigation': result.model_dump(mode='json')}, result.baseline.findings
            result = service.scan(body.target_url, **options)
            return {'baseline': result.model_dump(mode='json'), 'investigation': None}, result.findings
        return jobs.submit(operation)

    @app.get('/v1/jobs/{job_id}')
    def job(job_id: str):
        return jobs.get(job_id)

    @app.get('/v1/findings/{finding_id}/spec')
    def download(finding_id: str):
        finding = jobs.finding(finding_id)
        spec = service.validate_spec(finding['spec'])
        return Response(spec.model_dump_json(indent=2) + '\n', media_type='application/json',
                        headers={'Content-Disposition': 'attachment; filename="patchproof-check.json"'})

    @app.post('/v1/findings/{finding_id}/rechecks', status_code=202)
    def recheck(finding_id: str, body: EmptyInput):
        finding = jobs.finding(finding_id)
        spec = service.validate_spec(finding['spec'])
        def operation():
            result = service.execute(spec, allow_local=settings.allow_local(spec.target_url))
            return {'result': result.model_dump(mode='json')}, ()
        return jobs.submit(operation, kind='recheck', finding_id=finding_id)

    return app
