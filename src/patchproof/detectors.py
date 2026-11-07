"""Versioned pure detectors. No network I/O or imported expressions."""
from .models import Spec, CheckRun, Evidence


class CSPRule:
    rule_id = 'http.csp.present'
    detector_version = '1'
    expected_condition = 'nonempty-content-security-policy'
    title = 'Missing Content-Security-Policy header'
    coverage = 'CSP header presence only; policy strength is not assessed.'
    remediation = 'Configure a nonempty Content-Security-Policy response header appropriate for this website.'

    def evaluate(self, evidence: Evidence, reason=None, parameters=None) -> CheckRun:
        applicability = 'evaluated'
        observed = None
        name = (parameters or {}).get('cookie_name')
        if reason is None:
            if evidence.status_code is None:
                reason = 'No response metadata available.'
            elif 300 <= evidence.status_code < 400:
                reason = 'Redirect response; redirects are not followed.'
            elif not 200 <= evidence.status_code < 300:
                reason = 'Unsuccessful response.'
        if reason:
            applicability = 'unverified'
        else:
            observed, reason, applicability = self.condition(evidence, name)
        return CheckRun(rule_id=self.rule_id, detector_version=self.detector_version,
                        applied=applicability == 'evaluated', applicability=applicability,
                        observed_condition=observed, evidence=evidence, reason=reason,
                        cookie_name=name, coverage=self.coverage, remediation=self.remediation)

    def condition(self, evidence, name):
        if not evidence.is_html:
            return None, 'Response is not HTML.', 'unverified'
        if evidence.csp_present is None:
            return None, 'CSP evidence is unavailable.', 'unverified'
        return evidence.csp_present, None, 'evaluated'


class HSTSRule(CSPRule):
    rule_id = 'http.hsts.present'
    expected_condition = 'nonempty-strict-transport-security'
    title = 'Missing Strict-Transport-Security header'
    coverage = 'HSTS header presence on successful HTTPS responses only; policy strength is not assessed.'
    remediation = 'Configure a nonempty Strict-Transport-Security header appropriate for this HTTPS website.'

    def condition(self, evidence, name):
        if evidence.is_https is False:
            return None, 'Requires HTTPS; skipped on HTTP.', 'skipped'
        if evidence.is_https is None or evidence.hsts_present is None:
            return None, 'HSTS evidence is unavailable.', 'unverified'
        return evidence.hsts_present, None, 'evaluated'


class SessionCookieRule(CSPRule):
    rule_id = 'http.session-cookie.secure'
    expected_condition = 'all-observed-instances-secure'
    title = 'Session cookie issued without Secure'
    coverage = 'Secure attribute on explicitly named cookies issued by a successful HTTPS response only.'
    remediation = 'Set Secure on every issued instance of the configured session cookie.'

    def evaluate(self, evidence: Evidence, reason=None, parameters=None) -> CheckRun:
        if not (parameters or {}).get('cookie_name'):
            return CheckRun(rule_id=self.rule_id, applied=False, applicability='skipped',
                            observed_condition=None, evidence=evidence,
                            reason='No session cookie names configured.',
                            coverage=self.coverage, remediation=self.remediation)
        return super().evaluate(evidence, reason, parameters)

    def condition(self, evidence, name):
        if evidence.is_https is False:
            return None, 'Requires HTTPS; skipped on HTTP.', 'skipped'
        if evidence.is_https is None:
            return None, 'HTTPS evidence is unavailable.', 'unverified'
        cookie = next((item for item in evidence.cookies if item.name == name), None)
        if cookie is None:
            return None, 'Configured cookie evidence is unavailable.', 'unverified'
        if cookie.instances == 0:
            return None, 'Response did not issue the configured cookie.', 'skipped'
        # A definite insecure instance is enough to fail, even if another is malformed.
        if cookie.missing_secure:
            return False, None, 'evaluated'
        if cookie.unparseable:
            return None, 'A matching Set-Cookie field could not be evaluated.', 'unverified'
        return True, None, 'evaluated'


class MixedContentRule(CSPRule):
    rule_id = 'browser.mixed-content.references'
    expected_condition = 'no-http-resource-references'
    title = 'HTTP resource reference on an HTTPS page'
    coverage = ('Static document resource attributes and inline CSS during a bounded Chromium visit; '
                'JavaScript disabled, no crawling or authenticated sessions. Network outcomes do not determine the rule condition.')
    remediation = 'Replace HTTP resource references with HTTPS or remove them, then replay the same browser profile.'

    def evaluate(self, evidence, reason=None, parameters=None):
        browser = evidence.browser
        if evidence.is_https is False:
            applicability, observed, reason = 'skipped', None, 'Browser profile requires HTTPS.'
        elif browser and browser.availability == 'available' and browser.insecure_references:
            applicability, observed = 'evaluated', False
        elif (browser and browser.availability == 'available' and evidence.is_https is True
              and browser.navigation_ok and browser.coverage_complete and not browser.limit_reached
              and not browser.policy_blocked and not browser.browser_blocked):
            applicability, observed, reason = 'evaluated', True, None
        else:
            applicability, observed = 'unverified', None
            reason = reason or 'Browser coverage is incomplete or unavailable.'
        return CheckRun(rule_id=self.rule_id, applied=applicability == 'evaluated',
                        applicability=applicability, observed_condition=observed,
                        evidence=evidence, reason=reason, coverage=self.coverage,
                        remediation=self.remediation)


RULES = {(rule.rule_id, rule.detector_version): rule for rule in
         (CSPRule(), HSTSRule(), SessionCookieRule(), MixedContentRule())}


def resolve_rule(spec: Spec):
    rule = RULES.get((spec.rule_id, spec.detector_version))
    if rule is None or spec.method != 'GET' or spec.expected_condition != rule.expected_condition:
        raise ValueError('Invalid or unsupported CheckSpec.')
    return rule
