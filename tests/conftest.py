import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest


@pytest.fixture
def fixture_site():
    state = {'status': 200, 'type': 'text/html', 'csp': None, 'requests': 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state['requests'] += 1
            self.send_response(state['status'])
            self.send_header('Content-Type', state['type'])
            self.send_header('Set-Cookie', 'session=SECRET_COOKIE')
            self.send_header('Authorization', 'Bearer SECRET_TOKEN')
            self.send_header('Location', 'http://127.0.0.1:1/SECRET_LOCATION')
            if state['csp'] is not None:
                self.send_header('Content-Security-Policy', state['csp'])
            self.end_headers()
            try:
                self.wfile.write(b'SECRET_BODY')
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_port}/', state
    server.shutdown()
    server.server_close()
    thread.join()
