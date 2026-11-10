"""Optional per-execution accounting boundary. CLI/local calls have no guard."""
from contextvars import ContextVar
from contextlib import contextmanager

request_guard = ContextVar('patchproof_request_guard', default=None)

@contextmanager
def target_request(url):
    guard = request_guard.get()
    if guard is None:
        yield
    else:
        with guard('target', url):
            yield
