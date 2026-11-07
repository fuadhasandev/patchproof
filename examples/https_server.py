"""Controlled Phase 6 HTTPS fixture; no production use or system trust changes."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl

parser = argparse.ArgumentParser()
parser.add_argument('--cert', required=True)
parser.add_argument('--key', required=True)
args = parser.parse_args()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Security-Policy', "default-src * 'unsafe-inline'")
        self.send_header('Strict-Transport-Security', 'max-age=60')
        self.end_headers()
        body = '<p>Controlled HTTPS fixture</p>'
        if not Path('.demo-mixed-fixed').exists():
            body += '<img src="http://outside.invalid/image.png">'
        try:
            self.wfile.write(body.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(('127.0.0.1', 8765), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert, args.key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print('HTTPS fixture: https://127.0.0.1:8765 (touch .demo-mixed-fixed to remove the HTTP reference)')
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
