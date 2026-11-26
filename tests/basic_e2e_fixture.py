"""Test-only public-name routing; never deploy this entrypoint."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import uvicorn
from patchproof import collector
from patchproof.basic_api import create_app

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        if self.path == '/fixed':
            self.send_header('Content-Security-Policy', "default-src 'self'")
        self.end_headers()
    def log_message(self, *_):
        pass

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
real_resolve = collector.resolve

def resolve(host, port, allow_local):
    assert not allow_local
    if host == 'fixture.example':
        return socket.getaddrinfo('127.0.0.1', server.server_port, type=socket.SOCK_STREAM)[0]
    return real_resolve(host, port, allow_local)

collector.resolve = resolve
uvicorn.run(create_app(), host='127.0.0.1', port=8017, access_log=False)
