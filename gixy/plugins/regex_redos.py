import requests
import gixy
from gixy.plugins.plugin import Plugin
from gixy.directives.block import MapBlock

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
    the --regex-redos-url flag. This flag must specify the full URL to a
    service which can be queried with expressions, responding with a report
    matching the https://github.com/makenowjust-labs/recheck format.

    An implementation of a compatible server:
    https://github.com/MegaManSec/recheck-http-api
    """

    summary = (
        'Detect directives with regexes that are vulnerable to '
        'Regular Expression Denial of Service (ReDoS).'
    )
    severity = gixy.severity.HIGH
    unknown_severity = gixy.severity.UNSPECIFIED
    description = (
        'Regular expressions with the potential for catastrophic backtracking '
        'allow an nginx server to be denial-of-service attacked with very low '
        'resources (also known as ReDoS).'
    )
    help_url = 'https://joshua.hu/regex-redos-recheck-nginx-gixy'
    directives = ['location', 'server_name', 'proxy_redirect', 'if', 'rewrite', 'map']
    options = {
        'url': ""
    }
    skip_test = True

    def __init__(self, config):
        super(regex_redos, self).__init__(config)
        self.redos_server = self.config.get('url')

        self.cached_results = {}

    def audit(self, directive):
        # If we have no ReDoS check URL, skip.
        if not self.redos_server:
            return

        regex_patterns = set()
        child_val = {}

        if directive.name == 'server_name':
            for server_name in directive.args:
                if server_name[0] != '~':
                    continue
                # server_name www.example.com ~^www.\d+\.example\.com$;
                regex_patterns.add(server_name[1:])
        elif directive.name == 'proxy_redirect':
            if directive.args[0][0] == '~':
                # proxy_redirect ~^//(.*)$ $scheme://$1;
                if directive.args[0][1] == '*':
                    regex_patterns.add(directive.args[0][2:])
                else:
                    regex_patterns.add(directive.args[0][1:])
        elif directive.name == 'location':
            if directive.modifier in ['~', '~*']:
                # location ~ ^/example$ { }
                regex_patterns.add(directive.path)
        elif directive.name == 'if':
            if directive.operand in ['~', '~*', '!~', '!~*']:
                # if ($http_referer ~* ^https://example\.com/$") { }
                regex_patterns.add(directive.value)
        elif directive.name == 'rewrite':
            # rewrite ^/1(/.*) $1 break;
            regex_patterns.add(directive.pattern)
        elif isinstance(directive, MapBlock):
            for child in directive.children:
                for map_val in [child.source, child.destination]:
                    if map_val and map_val[0] == '~':
                        map_val = map_val[1:]
                        if map_val[0] == '*':
                            map_val = map_val[1:]
                        regex_patterns.add(map_val)
                        child_val[map_val] = child

        if not regex_patterns:
            return

        json_data = {}

        for regex_pattern in regex_patterns:
            if regex_pattern not in self.cached_results:
                json_data[regex_pattern] = {"pattern": regex_pattern, "modifier": ""}

        # Attempt to contact the ReDoS check server.
        try:
            response = requests.post(
                self.redos_server,
                json=json_data,
                headers={"Content-Type": "application/json"},
                timeout=60
            )
        except requests.RequestException as e:
            fail_reason = f'HTTP request to "{self.redos_server}" failed: {e}'
            self.add_issue(directive=directive, reason=fail_reason, severity=self.unknown_severity)
            return

        # If we get a non-200 response, skip.
        if response.status_code != 200:
            fail_reason = f'HTTP request to "{self.redos_server}" with status code "{response.status_code}": {response.text}'
            self.add_issue(directive=directive, reason=fail_reason, severity=self.unknown_severity)
            return

        # Attempt to parse the JSON response.
        try:
            response_json = response.json()
        except ValueError as e:
            fail_reason = f'Failed to parse JSON "{e}": "{response.text}"'
            self.add_issue(directive=directive, reason=fail_reason, severity=self.unknown_severity)
            return

        unchecked_patterns = set()

        for regex_pattern in regex_patterns:
            if regex_pattern in self.cached_results:
                continue
            if (
                regex_pattern not in response_json or
                response_json[regex_pattern] is None or
                "source" not in response_json[regex_pattern] or
                response_json[regex_pattern]["source"] != regex_pattern
            ):
                if regex_pattern not in unchecked_patterns:
                    unchecked_patterns.add(regex_pattern)

        if unchecked_patterns:
            unchecked_patterns = '", "'.join(unchecked_patterns)
            fail_reason = 'Could not check expression(s) "{unchecked_patterns}" for ReDoS.'.format(unchecked_patterns=unchecked_patterns)
            self.add_issue(directive=directive, reason=fail_reason, severity=self.unknown_severity)

        vulnerable_patterns = set()
        unknown_patterns = set()

        for regex_pattern in regex_patterns:
            if regex_pattern in self.cached_results:
                if self.cached_results[regex_pattern] == "vulnerable":
                    vulnerable_patterns.add(regex_pattern)
                else:
                    continue
            elif regex_pattern not in unchecked_patterns:
                recheck = response_json[regex_pattern]
                status = recheck.get("status")

                if status == "unknown":
                    unknown_patterns.add(regex_pattern)
                    continue

                self.cached_results[regex_pattern] = status
                if status == "vulnerable":
                    vulnerable_patterns.add(regex_pattern)
                    continue

        if unknown_patterns:
            unknown_patterns_string = '", "'.join(unknown_patterns)
            fail_reason = 'Unknown complexity of expression(s) "{unknown_patterns}".'.format(unknown_patterns=unknown_patterns_string)
            self.add_issue(directive=[directive] + [child_val[mv] for mv in unknown_patterns if mv in child_val], reason=fail_reason, severity=self.unknown_severity)

        if vulnerable_patterns:
            vulnerable_patterns_string = '", "'.join(vulnerable_patterns)
            fail_reason = 'ReDoS possible due to expression(s) "{vulnerable_patterns}".'.format(vulnerable_patterns=vulnerable_patterns_string)
            self.add_issue(directive=[directive] + [child_val[mv] for mv in vulnerable_patterns if mv in child_val], reason=fail_reason, severity=self.severity)
