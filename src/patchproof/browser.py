"""Optional browser boundary. Only the isolated worker handles raw browser data."""
import json
import os
import signal
import subprocess
import sys
import threading
import tempfile
from pathlib import Path
from .models import BrowserEvidence, Evidence
from .policy import validate_url

PROFILE = 'chromium-static-v1'
RUNTIME_SECONDS = 20
_SLOT = threading.BoundedSemaphore(1)


def unavailable(reason, *, https=True):
    return Evidence(is_https=https, browser=BrowserEvidence()), reason


def collect_browser(target_url, *, allow_local=False):
    target_url = validate_url(target_url)
    if not target_url.startswith('https:'):
        return unavailable('Browser profile requires HTTPS.', https=False)
    if sys.platform != 'darwin' or not os.path.isfile('/usr/bin/sandbox-exec'):
        return unavailable('Browser unavailable: controlled egress requires the supported macOS sandbox.')
    if not _SLOT.acquire(blocking=False):
        return unavailable('Browser unavailable: local browser capacity reached.')
    process = None
    directory = None
    pid_file = None
    try:
        directory = tempfile.TemporaryDirectory(prefix='patchproof-egress-')
        pid_file = Path(directory.name) / 'browser.pid'
        # Secrets and debug logging settings must not reach the driver or Chromium.
        env = {key: value for key, value in os.environ.items() if key in
               {'PATH', 'HOME', 'TMPDIR', 'PLAYWRIGHT_BROWSERS_PATH', 'PATCHPROOF_BROWSER_CA_FILE', 'PATCHPROOF_CHROMIUM_EXECUTABLE'}}
        env['PATCHPROOF_BROWSER_PID_FILE'] = str(pid_file)
        env['TMPDIR'] = directory.name
        process = subprocess.Popen([sys.executable, '-m', 'patchproof.browser_worker'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True, env=env)
        output, _ = process.communicate(json.dumps({'target': target_url, 'allow_local': allow_local}),
                                         timeout=RUNTIME_SECONDS)
        if process.returncode or len(output) > 16384:
            return unavailable('Browser unavailable: isolated collector did not complete.')
        data = json.loads(output)
        evidence = Evidence.model_validate_json(json.dumps(data['evidence']))
        # Worker emits only constant reasons and a strict typed evidence record.
        return evidence, data['reason']
    except subprocess.TimeoutExpired:
        return Evidence(is_https=True, browser=BrowserEvidence(availability='available', limit_reached=True)), 'Browser runtime limit reached; coverage incomplete.'
    except (OSError, ValueError, KeyError):
        return unavailable('Browser unavailable: install optional Playwright and Chromium and verify sandbox support.')
    finally:
        if process is not None:
            # Kill the entire owned process group, including orphaned driver/Chromium
            # children, on success, timeout, KeyboardInterrupt, or cancellation.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        # Playwright gives Chromium a separate process group. The trusted
        # launcher records that owned group before exec, including failed starts.
        try:
            browser_pid = int(pid_file.read_text()) if pid_file else 0
            if browser_pid > 1:
                os.killpg(browser_pid, signal.SIGKILL)
        except (OSError, ValueError):
            pass
        try:
            if directory is not None:
                directory.cleanup()
        finally:
            _SLOT.release()
