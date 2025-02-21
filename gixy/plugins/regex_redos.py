import requests
import gixy
from gixy.plugins.plugin import Plugin


class regex_redos(Plugin):
    r"""
    This plugin checks all directives for regular expressions that may be
    vulnerable to ReDoS (Regular Expression Denial of Service). ReDoS
    vulnerabilities may be used to overwhelm nginx servers with minimal
    resources from an attacker.

    Example of a vulnerable directive:
        location ~ ^/(a|aa|aaa|aaaa)+$

    Accessing the above location with a path such as
    /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab
    can result in catastrophic backtracking.

    This plugin relies on an external, public API to determine vulnerability.
    Because of this network-dependence, and the fact that potentially private
    expressions are sent over the network, usage of this plugin requires
    the --redos-checks-url flag. This flag must specify the full URL to a
    service which can be queried with expressions, responding with a report
    matching the https://github.com/makenowjust-labs/recheck format.

    An implementation of a compatible server:
    https://github.com/MegaManSec/redos-check-http
    """

    summary = (
        'Detect directives with regexes that are vulnerable to '
        'Regular Expression Denial of Service (ReDoS).'
    )
    severity = gixy.severity.HIGH
    unknown_severity = gixy.severity.LOW
    description = (
        'Regular expressions with the potential for catastrophic backtracking '
        'allow an nginx server to be denial-of-service attacked with very low '
        'resources (also known as ReDoS).'
    )
    help_url = 'https://joshua.hu/nginx-directives-regex-redos-denial-of-service-vulnerable'
    directives = ['location']  # XXX: server_name, rewrite, if, map, proxy_redirect
    options = {
        'url': ""
    }

    def __init__(self, config):
        super(regex_redos, self).__init__(config)
        self.redos_server = self.config.get('url')

    def audit(self, directive):
        # If we have no ReDoS check URL, skip.
        if not self.redos_server:
            return

        # Only process directives that have regex modifiers.
        if directive.modifier not in ('~', '~*'):
            return

        regex_pattern = directive.path

        # Attempt to contact the ReDoS check server.
        try:
            response = requests.post(
                self.redos_server,
                json={"1": regex_pattern},
                headers={"Content-Type": "application/json"},
                timeout=60
            )
        except requests.RequestException:
            return

        # If we get a non-200 response, skip.
        if response.status_code != 200:
            return

        # Attempt to parse the JSON response.
        try:
            response_json = response.json()
        except ValueError:
            reason = f'Could not check regex {regex_pattern} for ReDoS.'
            self.add_issue(directive=directive, reason=reason, severity=self.unknown_severity)
            return

        # Ensure the expected data structure is present and matches the pattern.
        if (
            "1" not in response_json or
            response_json["1"] is None or
            response_json["1"]["source"] != regex_pattern
        ):
            return

        recheck = response_json["1"]
        status = recheck.get("status")

        # If status is neither 'vulnerable' nor 'unknown', skip.
        if status not in ("vulnerable", "unknown"):
            return

        # If the status is unknown, add a low-severity issue.
        if status == "unknown":
            reason = f'Could not check complexity of regex {regex_pattern}.'
            self.add_issue(directive=directive, reason=reason, severity=self.unknown_severity)
            return

        # Status is 'vulnerable' here. Report as a high-severity issue.
        complexity_summary = recheck.get("complexity", {}).get("summary", "unknown")
        reason = f'Regex is vulnerable to {complexity_summary} ReDoS: {regex_pattern}.'
        self.add_issue(directive=directive, reason=reason, severity=self.severity)
