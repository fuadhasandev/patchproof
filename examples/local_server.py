"""Local demo: touching .demo-csp enables CSP on the same URL."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        if Path('.demo-csp').exists():
            self.send_header('Content-Security-Policy', "default-src 'self'")
        self.end_headers()
        self.wfile.write(b'<h1>PatchProof local fixture</h1>')

    def log_message(self, *_):
        pass


if __name__ == '__main__':
    print('Fixture: http://127.0.0.1:8765 (Ctrl-C to stop)', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
