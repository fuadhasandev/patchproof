"""Fixed-endpoint OpenRouter adapter; no target configuration or tool execution."""
import os
import httpx

ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions'


class ProviderError(Exception):
    """Sanitized provider failure; never includes credentials or provider bodies."""


class OpenRouterClient:
    def __init__(self, api_key: str, model: str, *, timeout=20.0, max_tokens=2048):
        self._api_key = api_key
        self._model = model
        if not 0 < timeout <= 60 or not 1 <= max_tokens <= 2048:
            raise ValueError("Invalid model limits.")
        self.timeout, self.max_tokens = timeout, max_tokens
        self.last_usage = {}

    def complete(self, messages: list, tools: list) -> dict:
        self.last_usage = {}
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False, follow_redirects=False) as client:
                with client.stream('POST', ENDPOINT,
                    headers={'Authorization': 'Bearer ' + self._api_key},
                    json={'model': self._model, 'messages': messages, 'tools': tools,
                          'tool_choice': 'auto', 'parallel_tool_calls': False,
                          'max_tokens': self.max_tokens, 'stream': False}) as response:
                    response.raise_for_status()
                    data = bytearray()
                    for chunk in response.iter_bytes():
                        data.extend(chunk)
                        if len(data) > 262144:
                            raise ProviderError('Provider response exceeded the size limit.')
                    import json
                    payload = json.loads(data)
                    usage = payload.get('usage', {})
                    if isinstance(usage, dict):
                        self.last_usage = {k:v for k,v in usage.items() if k in ('prompt_tokens','completion_tokens')
                                           and type(v) is int and 0 <= v <= 1000000000}
                    message = payload['choices'][0]['message']
                    if not isinstance(message, dict):
                        raise ValueError
                    return message
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError):
            raise ProviderError('OpenRouter request failed or returned an invalid response.') from None


def from_environment():
    key = os.environ.get('OPENROUTER_API_KEY', '').strip()
    model = os.environ.get('OPENROUTER_MODEL', '').strip()
    return OpenRouterClient(key, model) if key and model else None
