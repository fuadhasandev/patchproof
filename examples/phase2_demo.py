"""Offline HTTPS CLI demo. Mocks transport metadata, never disables TLS verification."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import httpcore
from typer.testing import CliRunner
from patchproof.cli import app


def main():
    headers = [(b'content-type', b'text/html'),
               (b'set-cookie', b'sid=DEMO_VALUE; Expires=Wed, 09 Jun 2027 10:18:14 GMT')]
    requests = []

    class Response:
        status = 200
        def __init__(self):
            self.headers = list(headers)
        def close(self):
            pass

    def request(pool, request):
        requests.append(request)
        return Response()

    runner = CliRunner()

    def run(arguments, expected):
        result = runner.invoke(app, arguments)
        print('patchproof ' + ' '.join(arguments))
        print(result.output)
        print('Exit:', result.exit_code)
        assert result.exit_code == expected
        assert 'DEMO_VALUE' not in result.output

    with TemporaryDirectory() as work, patch.object(httpcore.ConnectionPool, 'handle_request', request):
        directory = Path(work) / 'checks'
        run(['scan', 'https://fixture.example/', '--session-cookie', 'sid',
             '--export-checks', str(directory)], 0)
        assert len(requests) == 1
        specs = {json.loads(path.read_text())['rule_id']: path for path in directory.glob('*.json')}
        cookie = str(specs['http.session-cookie.secure'])
        run(['replay', cookie, '--format', 'json'], 1)
        headers[-1] = (b'set-cookie', b'sid=DEMO_VALUE; Secure')
        run(['replay', cookie, '--format', 'json'], 0)
        headers.pop()
        run(['replay', cookie, '--format', 'json'], 2)
        print('Verified one request per run; cookie replay: still present → resolved → unverified.')


if __name__ == '__main__':
    main()
