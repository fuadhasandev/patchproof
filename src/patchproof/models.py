from typing import Literal
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from .policy import validate_url


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)


class CheckSpec(Model):
    schema_version: Literal['1'] = '1'
    rule_id: Literal['http.csp.present'] = 'http.csp.present'
    detector_version: Literal['1'] = '1'
    target_url: str
    method: Literal['GET'] = 'GET'
    expected_condition: Literal['nonempty-content-security-policy'] = 'nonempty-content-security-policy'

    @field_validator('target_url')
    @classmethod
    def target(cls, value):
        return validate_url(value)


class ExtendedCheckSpec(CheckSpec):
    schema_version: Literal['2'] = '2'
    rule_id: Literal['http.hsts.present', 'http.session-cookie.secure']
    expected_condition: Literal['nonempty-strict-transport-security', 'all-observed-instances-secure']
    parameters: dict[str, str]

    @model_validator(mode='after')
    def rule_parameters(self):
        from .cookies import validate_cookie_name
        if self.rule_id == 'http.hsts.present':
            if self.parameters or self.expected_condition != 'nonempty-strict-transport-security':
                raise ValueError('Invalid HSTS rule parameters or expected condition.')
        else:
            if set(self.parameters) != {'cookie_name'} or self.expected_condition != 'all-observed-instances-secure':
                raise ValueError('Invalid cookie rule parameters or expected condition.')
            validate_cookie_name(self.parameters['cookie_name'])
        return self


Spec = CheckSpec | ExtendedCheckSpec


class CookieEvidence(Model):
    name: str
    instances: int
    missing_secure: int
    unparseable: int


class Evidence(Model):
    is_https: bool | None = None
    hsts_present: bool | None = None
    cookies: tuple[CookieEvidence, ...] = ()
    status_code: int | None = None
    is_html: bool | None = None
    csp_present: bool | None = None


class CheckRun(Model):
    rule_id: str = 'http.csp.present'
    detector_version: str = '1'
    applicability: Literal['evaluated', 'skipped', 'unverified'] = 'evaluated'
    cookie_name: str | None = None
    coverage: str = 'CSP header presence only; policy strength is not assessed.'
    remediation: str = 'Configure a nonempty Content-Security-Policy response header appropriate for this website.'
    applied: bool
    observed_condition: bool | None
    evidence: Evidence
    reason: str | None = None


class Finding(Model):
    spec: Spec
    run: CheckRun
    title: str = 'Missing Content-Security-Policy header'
    category: str = 'configuration observation'
    suggested_fix: str = 'Configure a nonempty Content-Security-Policy response header appropriate for this website.'


class Result(Model):
    status: Literal['resolved', 'still_present', 'unverified', 'skipped']
    run: CheckRun
    finding: Finding | None = None


class ScanResult(Result):
    checks: tuple[Result, ...]
    findings: tuple[Finding, ...]
