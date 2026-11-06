"""Reduce individual Set-Cookie fields to value-free, conservative observations."""
import re

TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
COOKIE_VALUE = re.compile(r'[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*', re.ASCII)


def validate_cookie_name(name: str) -> str:
    if not isinstance(name, str) or not 1 <= len(name) <= 256 or not TOKEN.fullmatch(name):
        raise ValueError('Cookie names must be 1–256 ASCII token characters.')
    return name


def observe_cookies(fields: list[str], names: tuple[str, ...]):
    from .models import CookieEvidence

    observations = []
    for name in names:
        instances = missing = malformed = 0
        for field in fields:
            # Never split on commas: Expires contains a comma. Never retain values.
            parts = field.split(';')
            pair = parts[0].strip()
            candidate = pair.split('=', 1)[0].strip()
            if candidate != name:
                # A malformed field beginning with an exact name is inconclusive.
                match = re.match(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", pair)
                if not match or match.group() != name:
                    continue
            instances += 1
            valid = '=' in pair and candidate == name
            value = pair.partition('=')[2]
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            valid = valid and COOKIE_VALUE.fullmatch(value) is not None
            secure = False
            for part in parts[1:]:
                attribute = part.strip()
                if not attribute:
                    continue
                key, sep, attr_value = attribute.partition('=')
                if not TOKEN.fullmatch(key) or any(ord(c) < 32 or ord(c) > 126 for c in attr_value):
                    valid = False
                if key.lower() == 'secure':
                    if sep:
                        valid = False
                    else:
                        secure = True
            if not valid:
                malformed += 1
            elif not secure:
                missing += 1
        observations.append(CookieEvidence(name=name, instances=instances,
                                           missing_secure=missing, unparseable=malformed))
    return tuple(observations)
