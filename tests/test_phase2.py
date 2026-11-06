import json
import logging
import httpcore
import pytest
from typer.testing import CliRunner
from patchproof import scan, replay, export_check, export_checks
from patchproof.cli import app
from patchproof.service import load_spec, SpecError

runner = CliRunner()


@pytest.fixture
def snapshot(monkeypatch):
    state = {'status': 200, 'headers': [(b'content-type', b'text/html')], 'requests': []}

    class Response:
        def __init__(self):
            self.status = state['status']
            self.headers = list(state['headers'])
        def close(self):
            pass
        @property
        def stream(self):
            pytest.fail('Must not read the body')

    def request(pool, request):
        state['requests'].append(request)
        assert request.method == b'GET'
        return Response()

    monkeypatch.setattr(httpcore.ConnectionPool, 'handle_request', request)
    return state


def cookie_check(result, name='sid'):
    return next(c for c in result.checks if c.run.cookie_name == name)


def test_shared_snapshot_and_hsts(snapshot):
    result = scan('https://example.com', session_cookies=['sid', 'other'])
    assert len(snapshot['requests']) == 1
    assert len(result.checks) == 4
    assert result.checks[0].run.evidence == result.checks[1].run.evidence
    assert {f.spec.rule_id for f in result.findings} == {'http.csp.present', 'http.hsts.present'}
    assert result.checks[1].status == 'still_present'
    assert cookie_check(result).status == 'skipped'
    result = scan('http://example.com', session_cookies=['sid'])
    assert result.checks[1].status == 'skipped'
    assert 'HTTPS' in result.checks[1].run.reason
    assert cookie_check(result).status == 'skipped'


@pytest.mark.parametrize('header,expected', [(b'', 'still_present'), (b'  ', 'still_present'), (b'max-age=0', 'resolved')])
def test_hsts_presence_only(snapshot, header, expected):
    snapshot['headers'] = [(b'content-type', b'application/json'), (b'strict-transport-security', header)]
    result = scan('https://example.com')
    assert result.checks[0].status == 'unverified'  # CSP remains HTML-only
    assert result.checks[1].status == expected
    assert 'presence' in result.checks[1].run.coverage


@pytest.mark.parametrize('fields,expected,instances', [
    ([b'sid=SECRET; Secure', b'sid=OTHER_SECRET; Path=/'], 'still_present', 2),
    ([b'sid=SECRET; Secure', b'sid=OTHER_SECRET; secure'], 'resolved', 2),
    ([b'sid=SECRET; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Secure'], 'resolved', 1),
    ([b'SID=SECRET; Secure'], 'skipped', 0),
    ([b'sid="SECRET; Secure'], 'unverified', 1),
    ([b'sid; Secure'], 'unverified', 1),
    ([b'sid=SECRET; Secure=yes'], 'unverified', 1),
    ([b'sid=SECRET; Secure', b'sid="broken; Secure'], 'unverified', 2),
    ([b'sid=SECRET', b'sid="broken; Secure'], 'still_present', 2),
    ([b'sid=SECRET, other=OTHER_SECRET; Secure'], 'unverified', 1),
])
def test_cookie_fields(snapshot, fields, expected, instances):
    snapshot['headers'] += [(b'set-cookie', field) for field in fields]
    result = scan('https://example.com', session_cookies=['sid'])
    check = cookie_check(result)
    assert check.status == expected
    assert check.run.evidence.cookies[0].instances == instances
    assert 'SECRET' not in result.model_dump_json()


def test_no_configuration(snapshot):
    snapshot['headers'].append((b'set-cookie', b'sid=SECRET'))
    result = scan('https://example.com')
    assert result.checks[-1].status == 'skipped'
    assert result.checks[-1].run.reason == 'No session cookie names configured.'
    assert result.run.evidence.cookies == ()


def test_cookie_replay(snapshot, tmp_path):
    snapshot['headers'].append((b'set-cookie', b'sid=SECRET'))
    result = scan('https://example.com', session_cookies=['sid'])
    finding = cookie_check(result).finding
    path = tmp_path / 'cookie.json'
    export_check(finding, path)
    assert json.loads(path.read_text())['parameters'] == {'cookie_name': 'sid'}
    assert replay(path).status == 'still_present'
    snapshot['headers'][-1] = (b'set-cookie', b'sid=NEW_SECRET; Secure')
    assert replay(path).status == 'resolved'
    snapshot['headers'].pop()
    missing = replay(path)
    assert missing.status == 'unverified'
    assert missing.run.applicability == 'skipped'
    assert 'did not issue' in missing.run.reason
    snapshot['headers'].append((b'set-cookie', b'sid="broken; Secure'))
    assert replay(path).status == 'unverified'
    snapshot['status'] = 302
    assert replay(path).status == 'unverified'


def test_exports_cli_and_privacy(snapshot, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    snapshot['headers'] += [(b'set-cookie', b'sid=SECRET_SESSION; Expires=Wed, 09 Jun 2027 10:18:14 GMT'),
                            (b'set-cookie', b'other=SECRET_OTHER'), (b'authorization', b'SECRET_AUTH')]
    target = ['scan', 'https://example.com', '--session-cookie', 'sid', '--session-cookie', 'other']
    single = tmp_path / 'one.json'
    response = runner.invoke(app, target + ['--export-check', str(single)])
    assert response.exit_code == 2
    assert '--export-checks DIR' in response.output
    assert not single.exists()
    directory = tmp_path / 'checks'
    response = runner.invoke(app, target + ['--export-checks', str(directory), '--format', 'json'])
    assert response.exit_code == 0, response.output
    data = json.loads(response.output)
    assert len(data['findings']) == 4
    paths = sorted(directory.glob('*.json'))
    assert len(paths) == 4
    assert all(load_spec(p) for p in paths)
    assert 'SECRET' not in response.output + caplog.text + ''.join(p.read_text() for p in paths)
    text = runner.invoke(app, target).output
    for rule in ('http.csp.present', 'http.hsts.present', 'http.session-cookie.secure'):
        assert rule in text
    assert 'Evidence:' in text and 'Remediation:' in text and 'applicability:' in text
    assert 'SECRET' not in text
    before = {p: p.read_bytes() for p in paths}
    again = runner.invoke(app, target + ['--export-checks', str(directory)])
    assert again.exit_code == 2 and 'already exists' in again.output
    assert before == {p: p.read_bytes() for p in paths}
    assert len(snapshot['requests']) == 4


def test_cookie_cli_replay_exit_codes(snapshot, tmp_path):
    snapshot['headers'] += [(b'content-security-policy', b"default-src 'self'"),
                            (b'strict-transport-security', b'max-age=0'), (b'set-cookie', b'sid=SECRET')]
    path = tmp_path / 'cookie.json'
    created = runner.invoke(app, ['scan', 'https://example.com', '--session-cookie', 'sid', '--export-check', str(path)])
    assert created.exit_code == 0, created.output
    args = ['replay', str(path), '--format', 'json']
    assert runner.invoke(app, args).exit_code == 1
    snapshot['headers'][-1] = (b'set-cookie', b'sid=SECRET; Secure')
    assert runner.invoke(app, args).exit_code == 0
    snapshot['headers'].pop()
    absent = runner.invoke(app, args)
    assert absent.exit_code == 2
    assert json.loads(absent.output)['status'] == 'unverified'


def test_no_overwrite_single(snapshot, tmp_path):
    finding = scan('http://example.com').findings[0]
    path = tmp_path / 'existing.json'
    path.write_text('keep me')
    with pytest.raises(FileExistsError):
        export_check(finding, path)
    assert path.read_text() == 'keep me'


@pytest.mark.parametrize('parameters', [{}, {'cookie_name': ''}, {'cookie_name': 'bad name'},
    {'cookie_name': 'sid;Secure'}, {'cookie_name': 'sid', 'headers': 'x'}, {'cookie_name': 'a' * 257},
    {'cookie_name': 123}, {'cookie_name': '../path'}])
def test_invalid_parameters(tmp_path, parameters):
    payload = dict(schema_version='2', rule_id='http.session-cookie.secure', detector_version='1',
                   target_url='https://example.com/', method='GET',
                   expected_condition='all-observed-instances-secure', parameters=parameters)
    path = tmp_path / 'invalid.json'
    path.write_text(json.dumps(payload))
    with pytest.raises(SpecError):
        load_spec(path)


def test_old_literal_csp_spec(snapshot, tmp_path):
    path = tmp_path / 'old.json'
    path.write_text('{"schema_version":"1","rule_id":"http.csp.present","detector_version":"1",'
                    '"target_url":"https://example.com/","method":"GET",'
                    '"expected_condition":"nonempty-content-security-policy"}')
    assert replay(path).status == 'still_present'
    snapshot['headers'].append((b'content-security-policy', b'present'))
    assert replay(path).status == 'resolved'


def test_invalid_cookie_option_before_request(snapshot):
    response = runner.invoke(app, ['scan', 'https://example.com', '--session-cookie', 'bad;SECRET'])
    assert response.exit_code == 2
    assert not snapshot['requests']
    assert 'SECRET' not in response.output


def test_hsts_replay(snapshot, tmp_path):
    finding = scan('https://example.com').findings[1]
    path = tmp_path / 'hsts.json'
    export_check(finding, path)
    assert replay(path).status == 'still_present'
    snapshot['headers'].append((b'strict-transport-security', b'max-age=0'))
    assert replay(path).status == 'resolved'
    data = json.loads(path.read_text())
    data['target_url'] = 'http://example.com'
    path.write_text(json.dumps(data))
    assert replay(path).status == 'unverified'


def test_loopback_cli_options_one_real_request(fixture_site, tmp_path):
    url, state = fixture_site
    directory = tmp_path / 'checks'
    result = runner.invoke(app, ['scan', url, '--allow-local', '--session-cookie', 'sid',
                                 '--export-checks', str(directory), '--format', 'json'])
    assert result.exit_code == 0, result.output
    checks = json.loads(result.output)['checks']
    assert [check['status'] for check in checks] == ['still_present', 'skipped', 'skipped']
    assert state['requests'] == 1
    assert len(list(directory.glob('*.json'))) == 1


@pytest.mark.parametrize('field,value', [('schema_version', '3'), ('rule_id', 'unknown'),
    ('detector_version', '2'), ('expected_condition', 'arbitrary'), ('method', 'POST'),
    ('allow_local', True), ('headers', {'X-Token': 'SECRET'})])
def test_new_specs_reject_conflicts(tmp_path, field, value):
    payload = dict(schema_version='2', rule_id='http.session-cookie.secure', detector_version='1',
                   target_url='https://example.com/', method='GET',
                   expected_condition='all-observed-instances-secure', parameters={'cookie_name': 'sid'})
    payload[field] = value
    path = tmp_path / 'bad.json'
    path.write_text(json.dumps(payload))
    with pytest.raises(SpecError):
        load_spec(path)


def test_cookie_spec_cannot_authorize_loopback(fixture_site, tmp_path):
    url, state = fixture_site
    payload = dict(schema_version='2', rule_id='http.session-cookie.secure', detector_version='1',
                   target_url=url, method='GET', expected_condition='all-observed-instances-secure',
                   parameters={'cookie_name': 'sid'})
    path = tmp_path / 'cookie.json'
    path.write_text(json.dumps(payload))
    assert replay(path).status == 'unverified'
    assert state['requests'] == 0
    allowed = replay(path, allow_local=True)
    assert allowed.status == 'unverified'  # HTTP does not establish Secure on HTTPS
    assert allowed.run.applicability == 'skipped'
    assert state['requests'] == 1


def test_repeat_name_is_deduplicated(snapshot):
    snapshot['headers'].append((b'set-cookie', b'sid=SECRET'))
    result = scan('https://example.com', session_cookies=['sid', 'sid', 'SID'])
    assert len(result.checks) == 4
    assert cookie_check(result, 'sid').status == 'still_present'
    assert cookie_check(result, 'SID').status == 'skipped'
    assert len(snapshot['requests']) == 1
