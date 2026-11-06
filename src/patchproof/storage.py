"""Local versioned SQLite history. No network operations or automatic retries."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import uuid4

SCHEMA_VERSION = 1
DEFAULT_DATABASE = '.patchproof/history.sqlite3'


class Store:
    def __init__(self, path, *, recover=False):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self._lease = open(str(self.path) + '.lock', 'a')
        try:
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lease.close()
            raise ValueError('Database is already in use. Run one API process per database.') from None
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA foreign_keys=ON')
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise ValueError('Unsupported database schema version; use a compatible PatchProof release.')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            if version == 0:
                self.db.executescript('''
                    BEGIN IMMEDIATE;
                    CREATE TABLE jobs (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        id TEXT NOT NULL UNIQUE,
                        kind TEXT NOT NULL CHECK(kind IN ('scan','recheck')),
                        state TEXT NOT NULL CHECK(state IN ('queued','running','completed','failed','interrupted')),
                        created_at REAL NOT NULL, updated_at REAL NOT NULL, finished_at REAL,
                        target_url TEXT NOT NULL, inputs_json TEXT NOT NULL,
                        original_finding_id TEXT REFERENCES findings(id),
                        retry_of TEXT REFERENCES jobs(id),
                        baseline_json TEXT, report_json TEXT, error TEXT
                    );
                    CREATE TABLE findings (
                        id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
                        data_json TEXT NOT NULL
                    );
                    CREATE INDEX jobs_history ON jobs(kind, seq DESC);
                    CREATE INDEX jobs_rechecks ON jobs(original_finding_id, seq DESC);
                    CREATE INDEX findings_job ON findings(job_id);
                    CREATE TRIGGER immutable_finished_job BEFORE UPDATE ON jobs
                    WHEN OLD.state IN ('completed','failed','interrupted')
                    BEGIN SELECT RAISE(ABORT, 'Terminal jobs are immutable'); END;
                    CREATE TRIGGER immutable_baseline BEFORE UPDATE OF baseline_json ON jobs
                    WHEN OLD.baseline_json IS NOT NULL AND NEW.baseline_json IS NOT OLD.baseline_json
                    BEGIN SELECT RAISE(ABORT, 'Original baseline is immutable'); END;
                    CREATE TRIGGER immutable_finding BEFORE UPDATE ON findings
                    BEGIN SELECT RAISE(ABORT, 'Original findings are immutable'); END;
                    PRAGMA user_version=1;
                    COMMIT;
                ''')
            if recover:
                now = time.time()
                with self.db:
                    self.db.execute("UPDATE jobs SET state='interrupted', updated_at=?, finished_at=?, error=? WHERE state IN ('queued','running')",
                        (now, now, 'Interrupted by API shutdown or restart. No requests were resumed; retry explicitly.'))
        except Exception:
            if hasattr(self, 'db'):
                self.db.close()
            self._lease.close()
            raise

    def create(self, *, kind, target, inputs, finding_id=None, retry_of=None):
        job_id, now = uuid4().hex, time.time()
        with self.lock, self.db:
            self.db.execute('''INSERT INTO jobs(id,kind,state,created_at,updated_at,target_url,inputs_json,original_finding_id,retry_of)
                               VALUES(?,?,'queued',?,?,?,?,?,?)''',
                            (job_id, kind, now, now, target, json.dumps(inputs), finding_id, retry_of))
        return job_id

    def running(self, job_id):
        with self.lock, self.db:
            self.db.execute("UPDATE jobs SET state='running',updated_at=? WHERE id=? AND state='queued'", (time.time(),job_id))

    def _save_baseline(self, job_id, baseline):
        encoded = baseline.model_dump_json()
        row = self.db.execute('SELECT baseline_json FROM jobs WHERE id=?', (job_id,)).fetchone()
        if row['baseline_json'] is not None:
            if json.loads(row['baseline_json']) != json.loads(encoded):
                raise ValueError('Cannot replace an original baseline.')
            return
        self.db.execute('UPDATE jobs SET baseline_json=?,report_json=?,updated_at=? WHERE id=?',
            (encoded, json.dumps({'baseline': baseline.model_dump(mode='json'), 'investigation': None}), time.time(),job_id))
        for finding in baseline.findings:
            self.db.execute('INSERT INTO findings(id,job_id,data_json) VALUES(?,?,?)',
                            (uuid4().hex, job_id, finding.model_dump_json()))

    def checkpoint(self, job_id, baseline):
        with self.lock, self.db:
            self._save_baseline(job_id, baseline)

    def complete(self, job_id, report, baseline=None):
        with self.lock, self.db:
            if baseline is not None:
                self._save_baseline(job_id, baseline)
            now = time.time()
            self.db.execute("UPDATE jobs SET state='completed',report_json=?,updated_at=?,finished_at=? WHERE id=?",
                            (json.dumps(report),now,now,job_id))

    def fail(self, job_id):
        with self.lock, self.db:
            now = time.time()
            self.db.execute("UPDATE jobs SET state='failed',error=?,updated_at=?,finished_at=? WHERE id=?",
                            ('Job failed; any saved baseline remains available.',now,now,job_id))

    @staticmethod
    def _job(row):
        return {key: row[key] for key in ('id','kind','state','created_at','updated_at','finished_at','target_url','original_finding_id','retry_of','error')} | {
            'report': json.loads(row['report_json']) if row['report_json'] else None}

    def get(self, job_id):
        with self.lock:
            row = self.db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            if row is None:
                raise KeyError('Job not found.')
            job = self._job(row)
            job['findings'] = []
            for f in self.db.execute('SELECT * FROM findings WHERE job_id=? ORDER BY rowid', (job_id,)).fetchall():
                latest = self.db.execute('SELECT * FROM jobs WHERE original_finding_id=? ORDER BY seq DESC LIMIT 1', (f['id'],)).fetchone()
                finding = {'id': f['id'], **json.loads(f['data_json'])}
                finding['latest_recheck'] = self._job(latest) if latest else None
                job['findings'].append(finding)
            return job

    def finding(self, finding_id):
        with self.lock:
            row = self.db.execute('SELECT data_json FROM findings WHERE id=?', (finding_id,)).fetchone()
            if row is None:
                raise KeyError('Finding not found.')
            return {'id': finding_id, **json.loads(row[0])}

    def retry_inputs(self, job_id):
        with self.lock:
            row = self.db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            if row is None:
                raise KeyError('Job not found.')
            return self._job(row), json.loads(row['inputs_json'])

    def page(self, *, limit=20, before=None, finding_id=None):
        if not 1 <= limit <= 50:
            raise ValueError('Page size must be between 1 and 50.')
        with self.lock:
            condition = 'j.kind=?' if finding_id is None else 'j.original_finding_id=?'
            args = ['scan' if finding_id is None else finding_id]
            if before:
                cursor = self.db.execute('SELECT seq FROM jobs WHERE id=?', (before,)).fetchone()
                if cursor is None:
                    raise ValueError('Unknown history cursor.')
                condition += ' AND j.seq < ?'
                args.append(cursor[0])
            rows = self.db.execute(f'''SELECT j.*, (SELECT count(*) FROM findings f WHERE f.job_id=j.id) AS finding_count
                                      FROM jobs j WHERE {condition} ORDER BY j.seq DESC LIMIT ?''', (*args, limit+1)).fetchall()
            items = []
            for row in rows[:limit]:
                if finding_id:
                    item = self._job(row)
                else:
                    item = {k: row[k] for k in ('id','target_url','created_at','state','finding_count','retry_of')}
                items.append(item)
            return {'items': items, 'next_cursor': items[-1]['id'] if len(rows)>limit else None}

    def close(self):
        with self.lock:
            self.db.close()
            self._lease.close()


def main():
    parser = argparse.ArgumentParser(description='Initialize/migrate local SQLite history without running jobs.')
    parser.add_argument('command', choices=['init'])
    parser.add_argument('--database', default=os.environ.get('PATCHPROOF_DB_PATH', DEFAULT_DATABASE))
    args = parser.parse_args()
    store = Store(args.database)
    store.close()
    print(f'SQLite schema {SCHEMA_VERSION} ready. No network requests were made.')


if __name__ == '__main__':
    main()
