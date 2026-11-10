"""Test-only adapters. Never shipped as a runtime entry point or deployment setting."""
import json
import os
import sys
import time
from urllib.request import urlopen

CONTROL='http://127.0.0.1:8776'
if sys.argv[1]=='control':
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='fixture',use='sig',alg='RS256')
    state={'fixed':False,'offline':False,'txt':[],'requests':0}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/jwks':data={'keys':[jwk]}
            elif self.path=='/token':data={'token':jwt.encode({'iss':CONTROL,'aud':'patchproof-api','sub':'fixture-user','iat':int(time.time()),'exp':int(time.time())+3600},key,algorithm='RS256',headers={'kid':'fixture'})}
            elif self.path=='/state':data=state
            elif self.path=='/target':
                state['requests']+=1
                self.send_response(503 if state['offline'] else 200);self.send_header('Content-Type','text/html')
                if state['fixed']:self.send_header('Content-Security-Policy',"default-src 'self'")
                self.send_header('Strict-Transport-Security','max-age=1');self.send_header('Set-Cookie','sid=HOSTED_SECRET_COOKIE')
                self.end_headers();self.wfile.write(b'HOSTED_SECRET_BODY');return
            else:self.send_error(404);return
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(data).encode())
        def do_POST(self):
            changes=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            state.update({k:v for k,v in changes.items() if k in ('fixed','offline','txt')})
            self.send_response(200);self.end_headers()
        def log_message(self,*args):pass
    ThreadingHTTPServer(('127.0.0.1',8776),Handler).serve_forever()
else:
    from patchproof.hosted.settings import Settings
    from patchproof.hosted import db
    settings=Settings(database_url=os.environ['PATCHPROOF_TEST_DATABASE_URL'],issuer=CONTROL,jwks_url=CONTROL+'/jwks',
        audience='patchproof-api',origin='http://localhost:3100',development=True)
    if sys.argv[1]=='api':
        from patchproof.hosted.api import create_app
        import uvicorn
        def resolver(name):
            with urlopen(CONTROL+'/state') as r:return json.load(r)['txt']
        uvicorn.run(create_app(settings,resolver=resolver),host='127.0.0.1',port=8000,access_log=False)
    elif sys.argv[1]=='worker':
        from patchproof.hosted.worker import Worker
        from patchproof import collector
        from patchproof.models import Evidence
        from urllib.error import HTTPError
        def fixture_metadata(*args,**kwargs):
            try:
                with urlopen(CONTROL+'/target') as r:
                    return Evidence(status_code=r.status,is_html=True,is_https=True,csp_present=bool(r.headers.get('Content-Security-Policy')),hsts_present=True),None
            except HTTPError:
                return Evidence(status_code=503,is_html=True,is_https=True), 'Unsuccessful response.'
        collector._collect=fixture_metadata
        os.environ.update(PATCHPROOF_DATABASE_URL=settings.database_url, PATCHPROOF_OIDC_ISSUER=settings.issuer,
            PATCHPROOF_OIDC_AUDIENCE=settings.audience, PATCHPROOF_OIDC_JWKS_URL=settings.jwks_url,
            PATCHPROOF_PUBLIC_ORIGIN=settings.origin, PATCHPROOF_HOSTED_DEV='1')
        from patchproof.hosted.worker import main
        main()
    elif sys.argv[1]=='init':
        from sqlalchemy import text
        from sqlalchemy.engine import make_url
        if not make_url(settings.database_url).database.startswith('patchproof_test'):raise ValueError('Test database required.')
        engine=db.engine(settings.database_url)
        with engine.begin() as conn:conn.execute(text('DROP SCHEMA public CASCADE'));conn.execute(text('CREATE SCHEMA public'))
        from patchproof.hosted.migrate import upgrade
        upgrade(settings.database_url)
