import json
import pytest
from patchproof.models import CheckSpec
from patchproof.service import load_spec, SpecError
from patchproof.policy import validate_url, PolicyError, allowed
from patchproof.cli import app
from typer.testing import CliRunner


@pytest.mark.parametrize('field,value', [('schema_version', '2'), ('rule_id', 'arbitrary'), ('detector_version', '2'), ('method', 'POST'), ('expected_condition', 'eval(1)'), ('allow_local', True), ('headers', {'Authorization': 'SECRET'}), ('run', {})])
def test_unsupported(tmp_path, field, value):
    data = CheckSpec(target_url='https://example.com').model_dump()
    data[field] = value
    path = tmp_path / 'check.json'
    path.write_text(json.dumps(data))
    with pytest.raises(SpecError):
        load_spec(path)
    result = CliRunner().invoke(app, ['replay', str(path), '--format', 'json'])
    assert result.exit_code == 2
    assert 'error' in json.loads(result.output)
    assert 'SECRET' not in result.output


@pytest.mark.parametrize('url', ['ftp://example.com', 'http://user:SECRET@example.com', 'http://example.com/?token=SECRET', 'http://example.com/?', 'http://example.com/#x', 'http://', 'http://example.com:0', 'http://example.com:99999', 'http://example.com:', 'http://exa\\mple.com', 'http://example.com/\n', 'http://[fe80::1%25en0]/'])
def test_bad_urls(url):
    with pytest.raises(PolicyError):
        validate_url(url)


@pytest.mark.parametrize('ip', ['10.0.0.1', '169.254.169.254', '0.0.0.0', '192.168.1.1', '::', 'fe80::1', 'fc00::1', '224.0.0.1', '100.64.0.1', '::ffff:10.0.0.1'])
def test_private_blocked_even_with_exception(ip):
    assert not allowed(ip, False)
    assert not allowed(ip, True)


@pytest.mark.parametrize('ip', ['127.0.0.1', '::1', '::ffff:127.0.0.1'])
def test_loopback(ip):
    assert not allowed(ip, False)
    assert allowed(ip, True)


def test_invalid_json(tmp_path):
    path = tmp_path / 'invalid.json'
    path.write_text('{SECRET')
    with pytest.raises(SpecError, match='Invalid or unsupported'):
        load_spec(path)


@pytest.mark.parametrize('missing', list(CheckSpec.model_fields))
def test_incomplete_spec(tmp_path, missing):
    data = CheckSpec(target_url='https://example.com').model_dump()
    del data[missing]
    path = tmp_path / 'partial.json'
    path.write_text(json.dumps(data))
    with pytest.raises(SpecError):
        load_spec(path)


@pytest.mark.parametrize('host', ['a..com', '-bad.com', 'bad-.com', 'bad_host.com', 'a' * 64 + '.com'])
def test_malformed_hostname(host):
    with pytest.raises(PolicyError):
        validate_url('https://' + host)
