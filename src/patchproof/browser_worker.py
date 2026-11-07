"""macOS network-denied Chromium + a synchronous, pinned policy GET broker.

No raw target data is emitted in reports or logs; browser temporary profiles
are owned by the parent and removed on completion, timeout, or cancellation. This module is private;
all public scan/replay paths run it inside the parent's hard process deadline.
"""
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import httpcore
from .collector import PolicyBackend
from .models import BrowserEvidence, Evidence
from .policy import PolicyError, validate_url

SANDBOX = '(version 1)(allow default)(deny network*)(allow network-bind network-inbound (local unix-socket))'
MAX_REQUESTS = 32
MAX_BYTES = 2 * 1024 * 1024
MAX_REFERENCES = 512
MAX_TOTAL_BYTES = 8 * 1024 * 1024


class CollectionLimit(Exception):
    pass
OBSERVATION_MS = 1000


def origin(url):
    value = urlsplit(url)
    return value.scheme, value.hostname, value.port or (443 if value.scheme == 'https' else 80)


def approved(url, target, method='GET'):
    try:
        return method == 'GET' and origin(validate_url(url)) == origin(target)
    except ValueError:
        return False


def sandbox_available():
    # A refused connection is NOT proof of isolation. Require EPERM/EACCES for
    # IPv4 and IPv6 socket operations under the identical inherited profile.
    probe = '''import errno,socket,sys
for family,addr in [(socket.AF_INET,('127.0.0.1',9)),(socket.AF_INET6,('::1',9))]:
 for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
  try:
   s=socket.socket(family,kind);s.settimeout(.2);s.connect(addr)
  except OSError as e:
   if e.errno not in (errno.EPERM,errno.EACCES): sys.exit(1)
  else: sys.exit(1)
sys.exit(0)
'''
    return subprocess.run(['/usr/bin/sandbox-exec', '-p', SANDBOX, sys.executable, '-c', probe],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode == 0


def fetch(url, *, allow_local, deadline, max_bytes=MAX_BYTES):
    """One GET, numeric validated connection, verified TLS, no proxy/cookies.

    Bytes and selected rendering headers are transient, never evidence. No
    automatic decompression, redirects, retries, or response cookie jar.
    """
    context = ssl.create_default_context(cafile=os.environ.get('PATCHPROOF_BROWSER_CA_FILE') or None)
    with httpcore.ConnectionPool(ssl_context=context, network_backend=PolicyBackend(allow_local, deadline),
                                retries=0, max_connections=1, max_keepalive_connections=0) as pool:
        with pool.stream('GET', url, headers={'User-Agent': 'PatchProof/0.1', 'Accept-Encoding': 'identity'},
                         extensions={'timeout': {'connect': 3, 'read': 3, 'write': 3, 'pool': 3}}) as response:
            if not 200 <= response.status < 300:
                if 300 <= response.status < 400:
                    raise PolicyError('Redirects are not followed.')
                raise ValueError('Unsuccessful response.')
            headers = {}
            for key, value in response.headers:
                key = key.decode('ascii').lower()
                if key == 'content-encoding' and value.lower().strip() not in (b'', b'identity'):
                    raise ValueError('Encoded response is outside the browser profile.')
                if key == 'content-disposition' and value.lower().strip().startswith(b'attachment'):
                    raise PolicyError('Downloads are disabled.')
                if key in {'content-type', 'content-security-policy', 'x-content-type-options'}:
                    decoded = value.decode('latin1')
                    headers[key] = headers[key] + ', ' + decoded if key == 'content-security-policy' and key in headers else decoded
            body = bytearray()
            for chunk in response.iter_stream():
                body.extend(chunk)
                if len(body) > min(MAX_BYTES, max_bytes) or time.monotonic() > deadline:
                    raise CollectionLimit()
            return response.status, headers, bytes(body)


# Read only resource-bearing attributes, not links/forms/arbitrary page text.
# Return raw references only inside this worker; persisted evidence is counts.
REFERENCES = r'''() => {
 const refs=[]; let unsupported=false;
 const add=(v)=>{try {const u=new URL(v,document.baseURI); if(u.protocol==='http:') refs.push(u.href);}catch{}};
 for(const e of document.querySelectorAll('img,script,iframe,frame,source,video,audio,track,input,embed,object,link,image,use')) {
   for(const a of ['src','poster','data','href','xlink:href']) {
     if(a==='href' && e.tagName==='LINK' && !/(stylesheet|icon|preload|modulepreload)/i.test(e.rel))continue;
     if(e.hasAttribute(a))add(e.getAttribute(a));
   }
   if(e.hasAttribute('srcset')) for(const v of e.getAttribute('srcset').split(',')) add(v.trim().split(/\s+/)[0]);
 }
 for(const e of document.querySelectorAll('[style],style')) {
   let css=e.style?.cssText || '';
   if(e.tagName==='STYLE') {try {css=[...e.sheet.cssRules].map(r=>r.cssText).join('\n');}catch{unsupported=true;}}
   for(const m of css.matchAll(/url\(\s*['"]?([^'"\s)]+)['"]?\s*\)/gi))add(m[1]);
   for(const m of css.matchAll(/@import\s*['"]([^'"]+)['"]/gi))add(m[1]);
 }
 return {refs:refs.slice(0,512),overflow:refs.length>512,unsupported:unsupported || !!document.querySelector('iframe,frame,object,embed')};
}'''


def run(target, allow_local):
    from playwright.sync_api import sync_playwright
    if not sandbox_available():
        return Evidence(is_https=True, browser=BrowserEvidence()), 'Browser unavailable: controlled egress self-test failed.'
    target = validate_url(target)
    deadline = time.monotonic() + 12
    counts = dict(requests=0, policy_blocked=0, browser_blocked=0, https_upgrades=0, http_loads=0)
    refs, failed_ids = set(), set()
    upgraded, browser_blocks = set(), set()
    incomplete = False
    limited = False
    navigation = False
    navigation_started = False
    status = None
    total_bytes = 0
    with tempfile.TemporaryDirectory(prefix='patchproof-browser-') as directory, sync_playwright() as pw:
        executable = os.environ.get('PATCHPROOF_CHROMIUM_EXECUTABLE') or pw.chromium.executable_path
        if not Path(executable).is_file():
            raise RuntimeError('Chromium missing')
        launcher = Path(directory) / 'chromium'
        pid_file = os.environ.get('PATCHPROOF_BROWSER_PID_FILE')
        record_pid = ('echo $$ > ' + shlex.quote(pid_file) + '\n') if pid_file else ''
        launcher.write_text('#!/bin/sh\n' + record_pid + 'exec /usr/bin/sandbox-exec -p ' + shlex.quote(SANDBOX) + ' ' + shlex.quote(executable) + ' "$@"\n')
        launcher.chmod(0o700)
        browser = pw.chromium.launch(executable_path=str(launcher), headless=True, timeout=5000,
            args=['--disable-quic', '--disable-background-networking', '--disable-extensions',
                  '--disable-component-update', '--disable-breakpad', '--no-proxy-server'])
        try:
            context = browser.new_context(java_script_enabled=False, service_workers='block',
                                          accept_downloads=False, ignore_https_errors=False)
            page = context.new_page()
            context.on('page', lambda other: other.close() if other != page else None)
            context.route_web_socket('**/*', lambda ws: ws.close())
            session = context.new_cdp_session(page)
            session.send('Network.enable')
            session.send('Audits.enable')
            def audit(event):
                details = event.get('issue', {}).get('details', {}).get('mixedContentIssueDetails')
                if not details:
                    return
                url = details.get('insecureURL', '')
                if not url.startswith('http:'):
                    return
                refs.add(url)
                resolution = details.get('resolutionStatus')
                if resolution == 'MixedContentAutomaticallyUpgraded':
                    upgraded.add(url)
                elif resolution == 'MixedContentBlocked':
                    browser_blocks.add(url)
            session.on('Audits.issueAdded', audit)
            session.on('Network.loadingFailed', lambda event: failed_ids.add(event['requestId'])
                       if event.get('blockedReason') == 'mixed-content' else None)

            def route_request(route):
                nonlocal incomplete, limited, total_bytes, navigation_started
                request = route.request
                counts['requests'] = min(512, counts['requests'] + 1)
                if request.url.startswith('http:'):
                    refs.add(request.url)
                if counts['requests'] > MAX_REQUESTS or time.monotonic() > deadline:
                    limited = incomplete = True
                    route.abort('blockedbyclient')
                    return
                # No iframe/subnavigation, downloads, non-GET, query, third-party,
                # or scheme-downgrade request may reach the broker.
                if (not approved(request.url, target, request.method) or
                    request.frame != page.main_frame or
                    (request.is_navigation_request() and (navigation_started or
                     urlsplit(request.url).path != (urlsplit(target).path or '/')))):
                    counts['policy_blocked'] += 1
                    incomplete = True
                    route.abort('blockedbyclient')
                    return
                if request.is_navigation_request():
                    navigation_started = True
                try:
                    code, headers, body = fetch(request.url, allow_local=allow_local, deadline=deadline, max_bytes=MAX_TOTAL_BYTES-total_bytes)
                    total_bytes += len(body)
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise CollectionLimit()
                    route.fulfill(status=code, headers=headers, body=body)
                except CollectionLimit:
                    limited = incomplete = True
                    route.abort('blockedbyclient')
                except PolicyError:
                    counts['policy_blocked'] += 1
                    incomplete = True
                    route.abort('blockedbyclient')
                except Exception:
                    incomplete = True
                    # Includes DNS, TLS and redirect failures: never copy errors.
                    route.abort('failed')

            def failed(request):
                nonlocal incomplete
                incomplete = True
            page.on('requestfailed', failed)
            context.route('**/*', route_request)
            try:
                response = page.goto(target, wait_until='load', timeout=8000)
                status = response.status if response else None
                navigation = response is not None and 200 <= status < 300 and 'text/html' in response.headers.get('content-type', '')
                page.wait_for_timeout(OBSERVATION_MS)
                observed = page.evaluate(REFERENCES)
                refs.update(observed['refs'])
                limited |= observed['overflow']
                incomplete |= not navigation or observed['unsupported']
            except Exception:
                incomplete = True
            counts['browser_blocked'] = min(512, max(len(failed_ids), len(browser_blocks)))
            incomplete |= bool(browser_blocks or failed_ids)
            # A matching HTTPS response substantiates an upgrade only with the
            # browser's structured mixed-content audit, not URL resemblance.
            counts['https_upgrades'] = min(512, len(upgraded))
            evidence = BrowserEvidence(availability='available', navigation_ok=navigation,
                coverage_complete=navigation and not incomplete and not limited,
                insecure_references=min(MAX_REFERENCES, len(refs)), limit_reached=limited, **counts)
            return Evidence(is_https=True, status_code=status, is_html=navigation, browser=evidence), (
                'Browser coverage incomplete: blocked dependency, navigation failure, or limit.'
                if not evidence.coverage_complete else None)
        finally:
            browser.close()


def main():
    try:
        data = json.loads(sys.stdin.read(8192))
        evidence, reason = run(data['target'], data['allow_local'])
    except Exception:
        evidence = Evidence(is_https=True, browser=BrowserEvidence())
        reason = 'Browser unavailable: install Playwright/Chromium and verify supported sandbox and TLS configuration.'
    print(json.dumps({'evidence': evidence.model_dump(mode='json'), 'reason': reason}))


if __name__ == '__main__':
    main()
