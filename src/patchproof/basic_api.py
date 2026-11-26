"""Stateless basic reports. Run one worker/instance for the process-wide limits."""
import asyncio
import hmac
import os
import time
import uuid
from collections import deque
from threading import BoundedSemaphore, Lock

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from . import service
from .policy import PolicyError, validate_url


class Submission(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_url: str = Field(min_length=1, max_length=2048)


def create_app(token=None):
    token = token or os.environ.get('PATCHPROOF_BASIC_TOKEN', '')
    if len(token) < 32:
        raise ValueError('PATCHPROOF_BASIC_TOKEN must contain at least 32 characters.')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    starts, lock, slots = deque(), Lock(), BoundedSemaphore(4)

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    @app.post('/v1/basic-reports')
    async def report(request: Request):
        if not hmac.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + token):
            raise HTTPException(401, 'Server credential required.')
        if request.headers.get('content-type', '').split(';')[0] != 'application/json':
            raise HTTPException(415, 'JSON required.')
        # Global quota cannot be bypassed by spoofing client forwarding headers.
        with lock:
            now = time.monotonic()
            while starts and starts[0] <= now - 60:
                starts.popleft()
            if len(starts) >= 30:
                raise HTTPException(429, 'Basic report rate limit reached.', headers={'Retry-After': '60'})
            starts.append(now)
        body = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 4096:
                        raise HTTPException(413, 'Request too large.')
        except TimeoutError:
            raise HTTPException(408, 'Request timed out.') from None
        try:
            data = Submission.model_validate_json(body)
            target = validate_url(data.target_url)
        except (ValidationError, PolicyError):
            raise HTTPException(422, 'Use an HTTP(S) URL without credentials, query, or fragment.') from None
        if not slots.acquire(blocking=False):
            raise HTTPException(429, 'Basic report capacity reached.', headers={'Retry-After': '5'})

        def check():
            try:
                # No fixture/environment bypass, browser, AI, persistence, or follow-up GET.
                baseline = service.scan(target)
                return {'id': uuid.uuid4().hex, 'kind': 'scan', 'state': 'completed',
                        'target_url': target, 'created_at': time.time(), 'retry_of': None,
                        'error': None, 'findings': [], 'report': {'baseline': baseline.model_dump(mode='json')}}
            finally:
                slots.release()

        from fastapi.responses import JSONResponse
        return JSONResponse(await run_in_threadpool(check), headers={'Cache-Control': 'no-store'})

    return app
