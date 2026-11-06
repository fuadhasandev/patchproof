from typing import Literal
from pydantic import BaseModel, ConfigDict, field_validator
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


class Evidence(Model):
    status_code: int | None = None
    is_html: bool | None = None
    csp_present: bool | None = None


class CheckRun(Model):
    rule_id: str = 'http.csp.present'
    applied: bool
    observed_condition: bool | None
    evidence: Evidence
    reason: str | None = None


class Finding(Model):
    spec: CheckSpec
    run: CheckRun
    title: str = 'Missing Content-Security-Policy header'
    category: str = 'configuration observation'
    suggested_fix: str = 'Configure a nonempty Content-Security-Policy response header appropriate for this website.'


class Result(Model):
    status: Literal['resolved', 'still_present', 'unverified']
    run: CheckRun
    finding: Finding | None = None
