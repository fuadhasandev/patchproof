"""Separate worker process; never loaded by the API server."""
import json
import os
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert
from . import db
from .queue import Queue
from .settings import Settings
from .store import Stopped, Denied, Limited
from .. import service
from ..execution import request_guard
from ..models import ScanResult, BrowserCheckSpec, Evidence, BrowserEvidence
from ..investigation import investigate
from ..openrouter import OpenRouterClient


def event(name, **fields):
    # Only call with opaque IDs, fixed names and numeric counts, never exceptions.
    print(json.dumps({'event': name, **fields}), flush=True)


def unavailable(spec):
    return service.evaluate(spec, Evidence(is_https=spec.target_url.startswith('https:'), browser=BrowserEvidence()),
        'Hosted browser unavailable: deployed egress isolation is not verified.', replaying=True)


class Worker:
    def __init__(self, engine, settings, provider=None):
        self.engine, self.settings = engine, settings
        self.queue = Queue(engine, settings)
        self.provider = provider

    def execute(self, job):
        job_id, token = job['id'], job['lease_token']
        done = threading.Event()
        def heartbeat():
            while not done.wait(self.settings.heartbeat_seconds):
                try: self.queue.heartbeat(job_id, token)
                except Exception: return  # Further dispatch must still pass the DB fence.
        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
        @contextmanager
        def guard(kind, url):
            call_id = self.queue.reserve(job_id, token, kind, url)
            try:
                yield
            except BaseException:
                try: self.queue.call_done(job_id, token, call_id, uncertain=True)
                except Exception: pass
                raise
            else:
                self.queue.call_done(job_id, token, call_id, usage=getattr(provider, 'last_usage', {}) if kind=='model' else None)
        context = request_guard.set(guard)
        try:
            if job['kind'] == 'recheck':
                spec = service.validate_spec(job['inputs'])
                result = unavailable(spec) if isinstance(spec, BrowserCheckSpec) else service.execute(spec)
                report = {'result': result.model_dump(mode='json')}
            else:
                baseline = ScanResult.model_validate_json(json.dumps(job['baseline'])) if job['baseline'] else service.scan(
                    job['target_url'], session_cookies=job['inputs']['session_cookies'])
                self.queue.checkpoint(job_id, token, baseline)
                report = {'baseline': baseline.model_dump(mode='json'), 'investigation': None}
                if job['inputs'].get('browser'):
                    result = unavailable(BrowserCheckSpec(target_url=job['target_url']))
                    report['browser_result'] = result.model_dump(mode='json')
                if job['inputs'].get('ai'):
                    provider = self.provider
                    if provider is None and os.environ.get('OPENROUTER_API_KEY') and os.environ.get('OPENROUTER_MODEL'):
                        provider = OpenRouterClient(os.environ['OPENROUTER_API_KEY'], os.environ['OPENROUTER_MODEL'],
                            timeout=self.settings.model_timeout, max_tokens=self.settings.model_tokens)
                    if provider is not None:
                        class Accounted:
                            def complete(self, messages, tools):
                                with guard('model', job['target_url']):
                                    return provider.complete(messages, tools)
                        provider_for_run = Accounted()
                    else:
                        provider_for_run = None
                    ai = investigate(job['target_url'], baseline=baseline, provider=provider_for_run,
                                     session_cookies=job['inputs']['session_cookies'])
                    report['investigation'] = ai.model_dump(mode='json')
            self.queue.finish(job_id, token, report=report)
            event('job_finished', job_id=job_id, request_id=job.get('request_id'), attempt=job['attempts'])
        except (Stopped, Denied, Limited):
            try: self.queue.finish(job_id, token, error='Execution stopped by cancellation, authorization or budget policy; outcome unverified.')
            except Stopped: pass
        except Exception:
            # Preserve the checkpoint. Unknown infrastructure errors leave the lease
            # to expire: bounded recovery can retry, but never repeats a model call.
            event('job_interrupted', job_id=job_id, attempt=job['attempts'])
        finally:
            request_guard.reset(context)
            done.set(); thread.join(timeout=2)

    def once(self):
        job = self.queue.claim()
        if job: self.execute(job)
        return job


def main():
    settings = Settings.from_environment()
    engine = db.engine(settings.database_url)
    from .api import ready
    ready(engine)
    worker = Worker(engine, settings)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    worker_id = db.ident()
    with ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
        futures = set()
        while not stop.is_set():
            futures = {f for f in futures if not f.done()}
            try:
                with engine.begin() as conn:
                    conn.execute(insert(db.workers).values(id=worker_id, heartbeat_at=db.now(conn), active=len(futures))
                        .on_conflict_do_update(index_elements=['id'], set_={'heartbeat_at':db.now(conn),'active':len(futures)}))
                if len(futures) < settings.concurrency:
                    job = worker.queue.claim()
                    if job:
                        futures.add(pool.submit(worker.execute, job)); continue
            except Exception:
                event('worker_infrastructure_unavailable', worker_id=worker_id)
            stop.wait(1)
        event('worker_draining', worker_id=worker_id, active=len(futures))
    engine.dispose()

if __name__ == '__main__': main()
