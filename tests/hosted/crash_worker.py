"""SIGKILL acceptance helper using a mocked billed provider call."""
import os
import time
from pathlib import Path
from patchproof.hosted.settings import Settings
from patchproof.hosted.worker import Worker
from patchproof.hosted import db
from patchproof import collector
from patchproof.models import Evidence
settings=Settings(database_url=os.environ['PATCHPROOF_TEST_DATABASE_URL'],issuer='https://issuer.example/realms/test',
    jwks_url='https://issuer.example/jwks',audience='patchproof-api',origin='https://patchproof.example')
collector._collect=lambda *a,**k:(Evidence(status_code=200,is_https=True,is_html=True,csp_present=False,hsts_present=True),None)
class Provider:
    def complete(self,*args):
        Path(os.environ['PATCHPROOF_TEST_DISPATCH_MARKER']).write_text('dispatched')
        time.sleep(60)
Worker(db.engine(settings.database_url),settings,Provider()).once()
