"""Actual loopback HTTP + fake OpenRouter CLI demo. No API key or internet needed."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from typer.testing import CliRunner
from patchproof.cli import app
from patchproof import openrouter


def main():
    state = {'fixed': False, 'requests': 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state['requests'] += 1
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Set-Cookie', 'session=DEMO_SECRET')
            if state['fixed']:
                self.send_header('Content-Security-Policy', "default-src 'self'")
            self.end_headers()
        def log_message(self, *_):
            pass

    class FakeOpenRouter:
        turns = 0
        def complete(self, messages, tools):
            self.turns += 1
            assert 'DEMO_SECRET' not in json.dumps(messages)
            records = json.loads(messages[1]['content'])['evidence']
            evidence_id, record = next((k, v) for k, v in records.items() if v['rule_id'] == 'http.csp.present')
            if self.turns <= 2:
                if self.turns == 1:
                    name, args = 'get_evidence', {'evidence_id': evidence_id}
                else:
                    # Simulate a developer deploying a fix between baseline and replay.
                    state['fixed'] = True
                    name, args = 'rerun_check', {'check_id': record['check_id']}
                return {'content': None, 'tool_calls': [{'id': f'call_{self.turns}', 'type': 'function',
                        'function': {'name': name, 'arguments': json.dumps(args)}}]}
            followup = json.loads(messages[-1]['content'])
            return {'content': json.dumps({'claims': [{
                'evidence_ids': [followup['evidence_id']], 'outcome': followup['record']['status'],
                'explanation': 'The deterministic replay observed a nonempty CSP header after the simulated fix.'}],
                'limitations': ['presence_only', 'no_exploitation_assessment']})}

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}/'
        print('OpenRouter is FAKE; target requests use a real controlled loopback fixture.')
        with patch.object(openrouter, 'from_environment', return_value=FakeOpenRouter()):
            result = CliRunner().invoke(app, ['investigate', url, '--allow-local', '--format', 'text'])
        print(result.output)
        assert result.exit_code == 0, result.exception
        assert state['requests'] == 2
        assert 'AI status: completed' in result.output
        assert 'DEMO_SECRET' not in result.output
        print('Verified baseline finding, requested evidence, requested replay, and final explanation; 2 target GETs.')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
