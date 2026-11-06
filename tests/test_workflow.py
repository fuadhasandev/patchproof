import json
import logging
import pytest
from typer.testing import CliRunner
from patchproof import scan, replay, export_check
from patchproof.cli import app

runner = CliRunner()


def test_full_cli_workflow(fixture_site, tmp_path, caplog):
    url, state = fixture_site
    path = tmp_path / 'check.json'
    caplog.set_level(logging.DEBUG)
    result = runner.invoke(app, ['scan', url, '--allow-local', '--format', 'json', '--export-check', str(path)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['status'] == 'still_present'
    spec = json.loads(path.read_text())
    assert set(spec) == {'schema_version', 'rule_id', 'detector_version', 'target_url', 'method', 'expected_condition'}
    result2 = runner.invoke(app, ['replay', str(path), '--allow-local', '--format', 'json'])
    assert result2.exit_code == 1
    assert json.loads(result2.output)['status'] == 'still_present'
    blocked = runner.invoke(app, ['replay', str(path), '--format', 'json'])
    assert blocked.exit_code == 2
    assert json.loads(blocked.output)['status'] == 'unverified'
    state['csp'] = "default-src 'self'"
    fixed = runner.invoke(app, ['replay', str(path), '--allow-local', '--format', 'json'])
    assert fixed.exit_code == 0
    assert json.loads(fixed.output)['status'] == 'resolved'
    assert state['requests'] == 3
    assert 'SECRET_' not in result.output + result2.output + fixed.output + path.read_text() + caplog.text


@pytest.mark.parametrize('status,content_type', [(302, 'text/html'), (500, 'text/html'), (200, 'application/json'), (204, '')])
def test_unverified(fixture_site, tmp_path, status, content_type):
    url, state = fixture_site
    finding = scan(url, allow_local=True).finding
    path = tmp_path / 'check.json'
    export_check(finding, path)
    state.update(status=status, type=content_type, csp='present')
    result = replay(path, allow_local=True)
    assert result.status == 'unverified'
    assert not result.run.applied
    assert result.run.observed_condition is None
    assert state['requests'] == 2  # no redirect follow


@pytest.mark.parametrize('header,expected', [(None, 'still_present'), ('   ', 'still_present'), ('weak-but-nonempty', 'resolved')])
def test_presence_only(fixture_site, header, expected):
    url, state = fixture_site
    state['csp'] = header
    assert scan(url, allow_local=True).status == expected


def test_no_local_permission(fixture_site):
    url, state = fixture_site
    assert scan(url).status == 'unverified'
    assert state['requests'] == 0
