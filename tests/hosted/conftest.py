import os
import json
import time
from types import SimpleNamespace
import pytest

pytest.importorskip('sqlalchemy')
pytest.importorskip('jwt')
from sqlalchemy import text
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from patchproof.hosted import db
from patchproof.hosted.settings import Settings
from patchproof.hosted.migrate import upgrade
from patchproof.hosted.api import create_app
from patchproof.hosted.auth import OIDC
from fastapi.testclient import TestClient

@pytest.fixture
def database():
    url=os.environ.get('PATCHPROOF_TEST_DATABASE_URL')
    if not url: pytest.skip('Set PATCHPROOF_TEST_DATABASE_URL to an isolated PostgreSQL test database.')
    from sqlalchemy.engine import make_url
    if not make_url(url).database.startswith('patchproof_test'):
        pytest.fail('Refusing to reset a database without patchproof_test prefix.')
    engine=db.engine(url)
    with engine.begin() as conn:
        conn.execute(text('DROP SCHEMA public CASCADE'))
        conn.execute(text('CREATE SCHEMA public'))
    upgrade(url)
    yield engine
    engine.dispose()

@pytest.fixture
def settings(database):
    return Settings(database_url=str(database.url.render_as_string(hide_password=False)),issuer='https://issuer.example/realms/test',
        jwks_url='https://issuer.example/jwks',audience='patchproof-api',origin='https://patchproof.example')

@pytest.fixture
def harness(database,settings,monkeypatch):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    auth=OIDC(settings)
    auth.keys=SimpleNamespace(get_signing_key_from_jwt=lambda token:SimpleNamespace(key=key.public_key()))
    records={}
    app=create_app(settings,engine=database,authenticator=auth,resolver=lambda name:records.get(name,[]))
    def token(subject='alice',**changes):
        claims={'iss':settings.issuer,'aud':settings.audience,'sub':subject,'iat':int(time.time()),'exp':int(time.time())+600,**changes}
        return jwt.encode(claims,key,algorithm='RS256')
    with TestClient(app) as client:
        def headers(subject='alice',key='submission-1'):
            return {'Authorization':'Bearer '+token(subject),'Origin':settings.origin,'Idempotency-Key':key}
        def create(subject='alice',host='fixture.example'):
            h=headers(subject)
            uid=client.get('/v2/me',headers=h).json()['id']
            p=client.post('/v2/projects',headers=h,json={'name':'Test project'});assert p.status_code==201,p.text
            project=p.json()['id']
            c=client.post(f'/v2/projects/{project}/targets',headers=h,json={'hostname':host});assert c.status_code==201,c.text
            target=c.json();records[target['record']]=[target['value']]
            assert client.post(f"/v2/targets/{target['id']}/verify",headers=h,json={}).status_code==200
            return uid,project,target['id']
        yield SimpleNamespace(client=client,headers=headers,create=create,token=token,records=records,engine=database,settings=settings)
