from dataclasses import dataclass, field
import os
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    database_url: str = field(repr=False)
    issuer: str = ''
    audience: str = ''
    jwks_url: str = ''
    origin: str = ''
    development: bool = False
    lease_seconds: int = 60
    heartbeat_seconds: int = 10
    concurrency: int = 2
    max_attempts: int = 3
    target_limit: int = 5
    model_limit: int = 3
    submissions_per_minute: int = 10
    targets_per_minute: int = 30
    models_per_day: int = 100
    challenge_seconds: int = 900
    verification_seconds: int = 86400
    model_timeout: int = 20
    model_tokens: int = 2048
    pending_limit: int = 100

    def __post_init__(self):
        if not self.database_url.startswith('postgresql+psycopg://') or 'REPLACE_' in self.database_url:
            raise ValueError('Hosted mode requires PostgreSQL via psycopg.')
        for name in ('issuer', 'jwks_url', 'origin'):
            value = getattr(self, name)
            parts = urlsplit(value)
            if parts.port is not None and not 1 <= parts.port <= 65535:
                raise ValueError(f'Invalid {name} port.')
            if (parts.scheme != 'https' and not (self.development and parts.scheme == 'http' and parts.hostname in ('localhost','127.0.0.1'))) or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
                raise ValueError(f'Invalid trusted {name} configuration.')
        if urlsplit(self.origin).path not in ('', '/') or self.origin.endswith('/'):
            raise ValueError('Origin must have no path or trailing slash.')
        if not self.audience:
            raise ValueError('OIDC audience required.')
        for name in ('lease_seconds','heartbeat_seconds','concurrency','max_attempts','target_limit','model_limit','submissions_per_minute','targets_per_minute','models_per_day','challenge_seconds','verification_seconds','model_timeout','model_tokens','pending_limit'):
            if not 1 <= getattr(self,name) <= 100000:
                raise ValueError(f'Invalid {name}.')
        if self.heartbeat_seconds * 3 >= self.lease_seconds or self.concurrency > 16 or self.model_limit > 3 or self.model_tokens > 2048 or self.model_timeout > 60 or self.max_attempts > 5:
            raise ValueError('Unsafe worker limits.')

    @classmethod
    def from_environment(cls):
        fields = dict(database_url=os.environ.get('PATCHPROOF_DATABASE_URL',''),
                      issuer=os.environ.get('PATCHPROOF_OIDC_ISSUER',''),
                      audience=os.environ.get('PATCHPROOF_OIDC_AUDIENCE',''),
                      jwks_url=os.environ.get('PATCHPROOF_OIDC_JWKS_URL',''),
                      origin=os.environ.get('PATCHPROOF_PUBLIC_ORIGIN',''),
                      development=os.environ.get('PATCHPROOF_HOSTED_DEV') == '1')
        for name in cls.__dataclass_fields__:
            if name not in fields:
                value = os.environ.get('PATCHPROOF_' + name.upper())
                if value is not None:
                    fields[name] = int(value)
        return cls(**fields)
