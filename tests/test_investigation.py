import copy
import json
import httpcore
import httpx
import pytest
from typer.testing import CliRunner
from patchproof import service
from patchproof import investigation as agent
from patchproof import openrouter
from patchproof.cli import app


class FakeProvider:
    def __init__(self, steps):
        self.steps = iter(steps)
        self.payloads = []

    def complete(self, messages, tools):
        self.payloads.append(copy.deepcopy({'messages': messages, 'tools': tools}))
        return next(self.steps)(messages)


def initial(messages):
    return json.loads(messages[1]['content'])['evidence']


def record_for(messages, rule='http.csp.present'):
    return next((eid, record) for eid, record in initial(messages).items() if record['rule_id'] == rule)


def tool(name, arguments, call_id='call_1'):
    return {'role': 'assistant', 'content': None, 'tool_calls': [
        {'id': call_id, 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}


def rerun(messages, call_id='call_1', rule='http.csp.present'):
    return tool('rerun_check', {'check_id': record_for(messages, rule)[1]['check_id']}, call_id)


def final(messages):
    if messages[-1]['role'] == 'tool':
        data = json.loads(messages[-1]['content'])
        eid, record = data['evidence_id'], data['record']
    else:
        eid, record = record_for(messages)
    return {'content': json.dumps({'claims': [{'evidence_ids': [eid], 'outcome': record['status'],
        'explanation': 'The referenced deterministic observation establishes this outcome.'}],
        'limitations': ['presence_only', 'no_exploitation_assessment']})}


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    monkeypatch.delenv('OPENROUTER_API_KEY', raising=False)
    monkeypatch.delenv('OPENROUTER_MODEL', raising=False)


def test_successful_followup(fixture_site):
    url, state = fixture_site
    def fix_and_rerun(messages):
        state['csp'] = "default-src 'self'"
        return rerun(messages)
    provider = FakeProvider([fix_and_rerun, final])
    result = agent.investigate(url, allow_local=True, provider=provider)
    assert result.baseline.findings[0].spec.rule_id == 'http.csp.present'
    assert result.ai_status == 'completed'
    assert result.followups[0].status == 'resolved'
    assert result.followup_requests == 1 and result.model_turns == 2
    assert state['requests'] == 2
    assert result.explanation.claims[0].evidence_ids[0] in result.evidence
    assert 'Advisory' in agent.render_investigation(result, 'text')


def test_get_evidence_no_request(fixture_site):
    url, state = fixture_site
    provider = FakeProvider([lambda m: tool('get_evidence', {'evidence_id': record_for(m)[0]}), final])
    result = agent.investigate(url, allow_local=True, provider=provider)
    assert result.ai_status == 'completed'
    assert state['requests'] == 1 and result.followup_requests == 0


@pytest.mark.parametrize('mutation', [
    lambda m: tool('rerun_check', {'check_id': record_for(m)[1]['check_id'], 'url': 'http://SECRET/'}),
    lambda m: tool('rerun_check', {'check_id': record_for(m)[1]['check_id'], 'allow_local': True}),
    lambda m: tool('rerun_check', {'check_id': record_for(m)[1]['check_id'], 'cookie_name': 'SECRET'}),
    lambda m: tool('rerun_check', {'check_id': record_for(m)[1]['check_id'], 'headers': {'secret': 'SECRET'}}),
    lambda m: tool('rerun_check', {'check_id': record_for(m)[1]['check_id'], 'method': 'POST'}),
    lambda m: tool('rerun_check', {'check_id': 'unknown'}),
    lambda m: tool('get_evidence', {'evidence_id': 'unknown'}),
    lambda m: tool('shell', {'command': 'SECRET'}),
    lambda m: tool('get_evidence', {'evidence_id': 123}),
    lambda m: tool('rerun_check', []),
])
def test_tool_scope_validation(fixture_site, mutation):
    url, state = fixture_site
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([mutation]))
    assert result.ai_status == 'invalid_tool'
    assert result.followup_requests == 0 and state['requests'] == 1
    assert 'SECRET' not in result.model_dump_json()


def test_malformed_json_tool_arguments(fixture_site):
    url, state = fixture_site
    def invalid(messages):
        message = rerun(messages)
        message['tool_calls'][0]['function']['arguments'] = '{SECRET'
        return message
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([invalid]))
    assert result.ai_status == 'invalid_tool' and state['requests'] == 1
    assert 'SECRET' not in result.model_dump_json()


def test_request_budget_and_failed_attempts(fixture_site, monkeypatch):
    url, state = fixture_site
    count = []
    def fail(spec, **kwargs):
        count.append((spec.target_url, kwargs))
        raise OSError('SECRET')
    monkeypatch.setattr(service, 'execute', fail)
    def batch(messages):
        calls = [rerun(messages, 'call_' + str(i))['tool_calls'][0] for i in range(3)]
        return {'tool_calls': calls}
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([batch]))
    assert result.ai_status == 'budget_exhausted'
    assert result.followup_requests == 2 and len(count) == 2
    assert all(target == url and options == {'allow_local': True} for target, options in count)
    assert all(r.status == 'unverified' for r in result.followups)
    assert agent.exit_code(result) == 2
    assert 'SECRET' not in result.model_dump_json()


def test_model_turn_budget(fixture_site):
    url, state = fixture_site
    provider = FakeProvider([lambda m, i=i: tool('get_evidence', {'evidence_id': record_for(m)[0]}, f'call_{i}') for i in range(3)])
    result = agent.investigate(url, allow_local=True, provider=provider)
    assert result.ai_status == 'budget_exhausted'
    assert len(provider.payloads) == 3 and state['requests'] == 1


@pytest.mark.parametrize('content', ['not json', '{"claims":[],"limitations":[]}',
    json.dumps({'claims': [{'evidence_ids': ['unknown'], 'outcome': 'resolved', 'explanation': 'SECRET'}], 'limitations': []})])
def test_invalid_final_falls_back(fixture_site, content):
    url, _ = fixture_site
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([lambda _: {'content': content}]))
    assert result.ai_status == 'invalid_response'
    assert result.explanation is None and result.baseline.findings
    assert 'SECRET' not in result.model_dump_json()


def test_claim_outcome_must_match(fixture_site):
    url, _ = fixture_site
    def false_claim(messages):
        reply = final(messages)
        body = json.loads(reply['content'])
        body['claims'][0]['outcome'] = 'resolved'
        return {'content': json.dumps(body)}
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([false_claim]))
    assert result.ai_status == 'invalid_response'


def test_provider_timeout_keeps_baseline(fixture_site):
    url, _ = fixture_site
    def timeout(_):
        raise httpx.ReadTimeout('SECRET_API_KEY')
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([timeout]))
    assert result.ai_status == 'provider_error' and result.baseline.findings
    assert result.model_turns == 1
    assert 'SECRET' not in result.model_dump_json()


def test_invalid_target_and_blocked_destination_never_call_provider(fixture_site):
    provider = FakeProvider([])
    with pytest.raises(ValueError):
        agent.investigate('https://user:SECRET@example.com', provider=provider)
    url, state = fixture_site
    result = agent.investigate(url, provider=provider)
    assert result.ai_status == 'target_blocked'
    assert not provider.payloads and state['requests'] == 0


def test_missing_config_cli_and_scan_replay_independent(fixture_site, tmp_path):
    url, _ = fixture_site
    runner = CliRunner()
    result = runner.invoke(app, ['investigate', url, '--allow-local', '--format', 'json'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['ai_status'] == 'not_configured'
    path = tmp_path / 'spec.json'
    assert runner.invoke(app, ['scan', url, '--allow-local', '--export-check', str(path)]).exit_code == 0
    assert runner.invoke(app, ['replay', str(path), '--allow-local']).exit_code == 1


def test_cli_invalid_input_is_json():
    result = CliRunner().invoke(app, ['investigate', 'https://example.com/?SECRET', '--format', 'json'])
    assert result.exit_code == 2
    assert 'error' in json.loads(result.output) and 'SECRET' not in result.output


def test_redaction_and_cookie_missing_followup(monkeypatch):
    headers = [(b'content-type', b'text/html'), (b'set-cookie', b'SECRET_NAME=SECRET_VALUE'),
               (b'authorization', b'SECRET_TOKEN'), (b'content-security-policy', b'SECRET_CSP')]
    class Response:
        status = 200
        def __init__(self):
            self.headers = headers.copy()
        def close(self):
            pass
    monkeypatch.setattr(httpcore.ConnectionPool, 'handle_request', lambda *a: Response())
    def stop_cookie(messages):
        headers.pop(1)
        return rerun(messages, rule='http.session-cookie.secure')
    provider = FakeProvider([stop_cookie, final])
    result = agent.investigate('https://secret-host.example/SECRET_PATH',
                               session_cookies=['SECRET_NAME'], provider=provider)
    assert result.followups[0].status == 'unverified'
    assert result.ai_status == 'completed'
    assert 'SECRET' not in json.dumps(provider.payloads)
    assert 'secret-host.example' not in json.dumps(provider.payloads)
    assert 'SECRET_VALUE' not in result.model_dump_json()
    assert agent.exit_code(result) == 2


def test_followup_rechecks_policy(fixture_site, monkeypatch):
    from patchproof import policy
    url, state = fixture_site
    def block_on_next(messages):
        monkeypatch.setattr(policy, 'allowed', lambda *a: False)
        return rerun(messages)
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([block_on_next, final]))
    assert state['requests'] == 1
    assert result.followup_requests == 1
    assert result.followups[0].status == 'unverified'
    assert 'blocked' in result.followups[0].run.reason


def test_adapter_wire_format(monkeypatch):
    captured = []
    def handler(request):
        captured.append(request)
        return httpx.Response(200, json={'choices': [{'message': {'content': '{}'}}]})
    real_client = httpx.Client
    def client(**kwargs):
        assert kwargs == {'timeout': 20.0, 'trust_env': False, 'follow_redirects': False}
        return real_client(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(openrouter.httpx, 'Client', client)
    adapter = openrouter.OpenRouterClient('SECRET_KEY', 'provider/model')
    assert adapter.complete([{'role': 'system', 'content': 'safe'}], agent.TOOLS) == {'content': '{}'}
    request = captured[0]
    assert str(request.url) == openrouter.ENDPOINT and request.method == 'POST'
    assert request.headers['authorization'] == 'Bearer SECRET_KEY'
    payload = json.loads(request.content)
    assert payload['tools'] == agent.TOOLS and payload['model'] == 'provider/model'
    assert payload['parallel_tool_calls'] is False and payload['max_tokens'] == 2048
    assert 'SECRET_KEY' not in request.content.decode()


def test_adapter_error_sanitized(monkeypatch):
    real_client = httpx.Client
    def timeout(request):
        raise httpx.ReadTimeout('SECRET')
    monkeypatch.setattr(openrouter.httpx, 'Client', lambda **kw: real_client(transport=httpx.MockTransport(timeout), **kw))
    with pytest.raises(openrouter.ProviderError) as caught:
        openrouter.OpenRouterClient('KEY', 'MODEL').complete([], agent.TOOLS)
    assert 'SECRET' not in str(caught.value)


def test_batch_validated_before_any_execution(fixture_site):
    url, state = fixture_site
    def mixed(messages):
        valid = rerun(messages)
        valid['tool_calls'] += tool('rerun_check', {'check_id': 'unknown'}, 'call_2')['tool_calls']
        return valid
    result = agent.investigate(url, allow_local=True, provider=FakeProvider([mixed]))
    assert result.ai_status == 'invalid_tool'
    assert result.followup_requests == 0 and state['requests'] == 1


def test_duplicate_call_id_rejected(fixture_site):
    url, state = fixture_site
    provider = FakeProvider([lambda m: tool('get_evidence', {'evidence_id': record_for(m)[0]}),
                             lambda m: tool('get_evidence', {'evidence_id': record_for(m)[0]})])
    result = agent.investigate(url, allow_local=True, provider=provider)
    assert result.ai_status == 'invalid_tool' and state['requests'] == 1


def test_unreachable_baseline_stays_unverified(monkeypatch):
    def unavailable(*a, **kw):
        raise httpcore.ConnectError('SECRET')
    monkeypatch.setattr(httpcore.ConnectionPool, 'handle_request', unavailable)
    result = agent.investigate('https://example.com', provider=FakeProvider([final]))
    assert result.baseline.status == 'unverified'
    assert result.explanation.claims[0].outcome == 'unverified'
    assert agent.exit_code(result) == 2
    assert 'SECRET' not in result.model_dump_json()


@pytest.mark.parametrize('response', [httpx.Response(401, text='SECRET'),
                                     httpx.Response(302, headers={'location': 'https://secret.example/'}),
                                     httpx.Response(200, text='invalid SECRET'),
                                     httpx.Response(200, content=b'x' * 262145)])
def test_adapter_rejects_bad_responses(monkeypatch, response):
    real_client = httpx.Client
    requests = []
    def handle(request):
        requests.append(request)
        return response
    monkeypatch.setattr(openrouter.httpx, 'Client', lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    with pytest.raises(openrouter.ProviderError) as caught:
        openrouter.OpenRouterClient('KEY', 'MODEL').complete([], agent.TOOLS)
    assert 'SECRET' not in str(caught.value)
    assert len(requests) == 1


def test_configuration_requires_both_settings(monkeypatch):
    assert openrouter.from_environment() is None
    monkeypatch.setenv('OPENROUTER_API_KEY', 'KEY')
    assert openrouter.from_environment() is None
    monkeypatch.setenv('OPENROUTER_MODEL', 'MODEL')
    assert isinstance(openrouter.from_environment(), openrouter.OpenRouterClient)
