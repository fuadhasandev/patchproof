"""Resource-server validation; OAuth2 Proxy owns the maintained OIDC login flow."""
import jwt
from jwt import PyJWKClient
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import select
from . import db

class AuthenticationError(Exception): pass

class OIDC:
    def __init__(self, settings):
        self.settings = settings
        self.keys = PyJWKClient(settings.jwks_url, cache_jwk_set=True, lifespan=300, timeout=5)

    def verify(self, token):
        try:
            key = self.keys.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=['RS256'], audience=self.settings.audience,
                issuer=self.settings.issuer, options={'require': ['exp','iat','iss','aud','sub']}, leeway=5)
            if not isinstance(claims['sub'], str) or not 1 <= len(claims['sub']) <= 255:
                raise ValueError
            return claims['sub']
        except Exception:
            raise AuthenticationError('Authentication required.') from None


def user_id(conn, issuer, subject):
    conn.execute(insert(db.users).values(id=db.ident(), issuer=issuer, subject=subject, created_at=db.now(conn))
                 .on_conflict_do_nothing(index_elements=['issuer','subject']))
    return conn.scalar(select(db.users.c.id).where(db.users.c.issuer == issuer, db.users.c.subject == subject))
