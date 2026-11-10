"""Initial hosted schema. v1 SQLite remains separate."""
from alembic import op
from patchproof.hosted.migrations.schema_v1 import metadata
revision = '0001_hosted'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    from sqlalchemy import inspect
    existing = set(inspect(op.get_bind()).get_table_names()) - {'alembic_version'}
    if existing:
        raise RuntimeError('Initial migration requires an empty dedicated database; existing tables were not changed.')
    op.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
    metadata.create_all(op.get_bind())
    # Immutable evidence and terminal records, including accidental direct writes.
    op.execute("""CREATE FUNCTION protect_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'Stored evidence is immutable'; END $$""")
    for table in ('findings', 'checkspecs'):
        op.execute(f'CREATE TRIGGER immutable_{table} BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION protect_evidence()')
    op.execute("""CREATE FUNCTION protect_job() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.state IN ('completed','failed','interrupted','cancelled') THEN
        RAISE EXCEPTION 'Terminal jobs are immutable';
      END IF;
      IF OLD.baseline IS NOT NULL AND NEW.baseline::text IS DISTINCT FROM OLD.baseline::text THEN
        RAISE EXCEPTION 'Original baseline is immutable';
      END IF;
      RETURN NEW;
    END $$""")
    op.execute('CREATE TRIGGER immutable_job BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION protect_job()')

def downgrade():
    raise RuntimeError('Destructive downgrade disabled. Restore a verified backup into a separate database.')
