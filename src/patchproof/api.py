"""Loopback-only HTTP application around the existing scan and replay services."""
import asyncio
import hmac
import ipaddress
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ._version import __version__
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import Field, field_validator
from . import service
from .investigation import investigate
from .models import Model
from .policy import validate_url
from .cookies import validate_cookie_name
from .storage import Store, DEFAULT_DATABASE


@dataclass(frozen=True)
class Settings:
    token: str = field(repr=False)
    fixture_origin: str | None = None
    workers: int = 1
    pending_limit: int = 8
    database_path: str = field(default_factory=lambda: os.environ.get('PATCHPROOF_DB_PATH', DEFAULT_DATABASE))

    def __post_init__(self):
        if len(self.token) < 32:
            raise ValueError('Set PATCHPROOF_API_TOKEN to at least 32 characters.')
        if self.fixture_origin:
            value = validate_url(self.fixture_origin)
            parts = urlsplit(value)
            if parts.path not in ('', '/') or not ipaddress.ip_address(parts.hostname).is_loopback:
                raise ValueError('Fixture origin must use a literal loopback IP and no path.')
            object.__setattr__(self, 'fixture_origin', origin(value))
        if self.workers != 1 or self.pending_limit <= 0:
            raise ValueError('Use one worker and a positive queue limit.')

    def allow_local(self, target):
        return self.fixture_origin is not None and origin(target) == self.fixture_origin


def origin(url):
    parsed = urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'


class ScanInput(Model):
    target_url: str = Field(max_length=2048)
    session_cookies: list[str] = Field(default_factory=list, max_length=16)
    ai: bool = False
    browser: bool = False

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
        self.store = Store(settings.database_path, recover=True)
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='patchproof')
        self.closed = False

    def submit(self, operation, *, inputs, target, kind='scan', finding_id=None, retry_of=None):
        with self.lock:
            if self.closed or not self.slots.acquire(blocking=False):
                raise HTTPException(429, 'Local job capacity reached. Wait for active jobs to finish.')
            job_id = None
            try:
                job_id = self.store.create(kind=kind, target=target, inputs=inputs,
                                           finding_id=finding_id, retry_of=retry_of)
                self.pool.submit(self._run, job_id, operation)
            except Exception:
                if job_id:
                    self.store.fail(job_id)
                self.slots.release()
                raise HTTPException(503, 'Job runner or local database unavailable.') from None
            return {'id': job_id, 'state': 'queued'}

    def _run(self, job_id, operation):
        try:
            self.store.running(job_id)
            report, baseline = operation(lambda result: self.store.checkpoint(job_id, result))
            self.store.complete(job_id, report, baseline)
        except Exception:
            self.store.fail(job_id)
        finally:
            self.slots.release()

    def get(self, job_id):
        try:
            return self.store.get(job_id)
        except KeyError:
            raise HTTPException(404, 'Job not found.') from None

    def finding(self, finding_id):
        try:
            return self.store.finding(finding_id)
        except KeyError:
            raise HTTPException(404, 'Finding not found.') from None

    def close(self):
        self.closed = True
        self.pool.shutdown(wait=True, cancel_futures=False)
        self.store.close()


def create_app(settings: Settings | None = None, *, provider=None):
    settings = settings or Settings(token=os.environ.get('PATCHPROOF_API_TOKEN', ''),
                                   fixture_origin=os.environ.get('PATCHPROOF_FIXTURE_ORIGIN') or None)
    jobs = Jobs(settings)

    @asynccontextmanager
    async def lifespan(app):
        yield
        await asyncio.to_thread(jobs.close)

    app = FastAPI(version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
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
                'fixture_origin': settings.fixture_origin, 'history_ttl_seconds': 0,
                'workers': settings.workers, 'pending_limit': settings.pending_limit, 'store_limit': 0,
                'browser': True, 'browser_profile': 'chromium-static-v1', 'persistent_history': True, 'schema_version': 1}

    def start_scan(body, retry_of=None):
        def operation(checkpoint):
            options = dict(allow_local=settings.allow_local(body.target_url), session_cookies=body.session_cookies)
            if body.ai:
                result = investigate(body.target_url, provider=provider, on_baseline=checkpoint, browser=body.browser, **options)
                return {'baseline': result.baseline.model_dump(mode='json'),
                        'investigation': result.model_dump(mode='json')}, result.baseline
            result = service.scan(body.target_url, browser=body.browser, **options)
            return {'baseline': result.model_dump(mode='json'), 'investigation': None}, result
        return jobs.submit(operation, inputs=body.model_dump(), target=body.target_url, retry_of=retry_of)

    @app.post('/v1/scans', status_code=202)
    def scan(body: ScanInput):
        return start_scan(body)

    @app.get('/v1/scans')
    def history(limit: int = Query(20, ge=1, le=50), before: str | None = Query(None, max_length=32)):
        try:
            return jobs.store.page(limit=limit, before=before)
        except ValueError:
            raise HTTPException(422, 'Invalid history cursor.') from None

    @app.get('/v1/jobs/{job_id}')
    def job(job_id: str):
        return jobs.get(job_id)

    @app.get('/v1/findings/{finding_id}/spec')
    def download(finding_id: str):
        finding = jobs.finding(finding_id)
        spec = service.validate_spec(finding['spec'])
        return Response(spec.model_dump_json(indent=2) + '\n', media_type='application/json',
                        headers={'Content-Disposition': 'attachment; filename="patchproof-check.json"'})

    def start_recheck(spec, finding_id, retry_of=None):
        def operation(checkpoint):
            result = service.execute(spec, allow_local=settings.allow_local(spec.target_url))
            return {'result': result.model_dump(mode='json')}, None
        return jobs.submit(operation, kind='recheck', finding_id=finding_id, inputs=spec.model_dump(),
                           target=spec.target_url, retry_of=retry_of)

    @app.post('/v1/findings/{finding_id}/rechecks', status_code=202)
    def recheck(finding_id: str, body: EmptyInput):
        finding = jobs.finding(finding_id)
        spec = service.validate_spec(finding['spec'])
        return start_recheck(spec, finding_id)

    @app.get('/v1/findings/{finding_id}/rechecks')
    def timeline(finding_id: str, limit: int = Query(20, ge=1, le=50), before: str | None = Query(None, max_length=32)):
        jobs.finding(finding_id)
        try:
            return jobs.store.page(limit=limit, before=before, finding_id=finding_id)
        except ValueError:
            raise HTTPException(422, 'Invalid history cursor.') from None

    @app.post('/v1/jobs/{job_id}/retry', status_code=202)
    def retry(job_id: str, body: EmptyInput):
        try:
            original, inputs = jobs.store.retry_inputs(job_id)
        except KeyError:
            raise HTTPException(404, 'Job not found.') from None
        if original['state'] not in ('failed', 'interrupted'):
            raise HTTPException(409, 'Only failed or interrupted jobs can be retried.')
        try:
            if original['kind'] == 'scan':
                return start_scan(ScanInput.model_validate(inputs), retry_of=job_id)
            spec = service.validate_spec(inputs)
            return start_recheck(spec, original['original_finding_id'], retry_of=job_id)
        except ValueError:
            raise HTTPException(422, 'Stored inputs are no longer supported.') from None

    return app
