"""Run once per deployment before starting API/workers; never on request startup."""
import os
from pathlib import Path
from alembic import command
from alembic.config import Config

def upgrade(url):
    config = Config()
    config.set_main_option('script_location', str(Path(__file__).with_name('migrations')))
    config.set_main_option('sqlalchemy.url', url.replace('%','%%'))
    command.upgrade(config, 'head')
    role = os.environ.get('PATCHPROOF_RUNTIME_ROLE')
    if role:
        import re
        from sqlalchemy import text
        from .db import engine, metadata
        if not re.fullmatch('[a-z_][a-z0-9_]{0,62}', role):
            raise ValueError('Invalid runtime role.')
        connection_engine = engine(url)
        with connection_engine.begin() as conn:
            conn.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
            for name in metadata.tables:
                conn.execute(text(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{name}" TO "{role}"'))
            conn.execute(text(f'GRANT SELECT ON TABLE alembic_version TO "{role}"'))
            conn.execute(text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{role}"'))
        connection_engine.dispose()

if __name__ == '__main__':
    upgrade(os.environ['PATCHPROOF_DATABASE_URL'])
