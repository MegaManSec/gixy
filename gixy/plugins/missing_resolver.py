import gixy
import gixy.core.builtin_variables as builtins
import re

from gixy.plugins.plugin import Plugin
from gixy.directives.directive import is_ipv6, is_ipv4
from gixy.core.variable import compile_script


class missing_resolver(Plugin):
    """
    Insecure example:
        proxy_pass https://example.com;
    """

    summary = "proxy_pass may use stale IP addresses for hostnames that are only resolved at start-up."
    severity = gixy.severity.LOW
    description = "Using proxy_pass with a static hostname, DNS is resolved only at startup, risking proxying to stale IPs. To ensure dynamic resolution, assign the hostname to a variable with 'set' and use the 'resolver' directive."
    help_url = "https://joshua.hu/nginx-dns-caching"
    directives = ["proxy_pass"]

    def __init__(self, config):
        super(missing_resolver, self).__init__(config)
        self.parse_uri_re = re.compile(r'^(?P<scheme>[a-z][a-z0-9+.-]*://)?(?P<host>\[[0-9a-fA-F:.]+\]|[^/?#:]+)(?::(?P<port>[0-9]+))?')
        self.local_suffixes = (
            ".intranet", ".internal", ".private", ".corp", ".home",
            ".lan", ".local", ".localhost", ".svc"
        )

    def audit(self, directive):
        if directive.args[0].startswith('unix:'):
            return

        parsed = self.parse_uri_re.match(directive.args[0])
        if not parsed:
            return

        parsed_host = parsed.group('host')
        parsed_host_compiled = compile_script(parsed_host) # proxy_pass $var <- $var may be a variable to an upstream (ugly, but valid).
        parsed_host = "" # this is fine, just ugly; parsed_host is only really used for upstream anyways
        for var in parsed_host_compiled:
            if var.name and builtins.is_builtin(var.name):
                break
            if not isinstance(var.final_value, str):
                break
            parsed_host += var.final_value


        if parsed_host == "":
            return

        if is_ipv6(parsed_host, False) or is_ipv4(parsed_host, False):
            return

        severity = self.severity

        upstream_directives = []
        found_upstream = False
        found_bad_server = False
        for upstream in directive.find_imperative_directives_in_scope("upstream", True):
            if getattr(upstream, "args", None) == [parsed_host]:
                found_upstream = True
                for child in upstream.children:
                    if child.name == 'server' and 'resolve' not in child.args:
                        if child.args[0].startswith('unix:'):
                            continue

                        parsed_upstream_server = self.parse_uri_re.match(child.args[0])
                        if not parsed_upstream_server:
                            continue

                        parsed_upstream_host = parsed_upstream_server.group('host')
                        if is_ipv6(parsed_upstream_host, False) or is_ipv4(parsed_upstream_host, False):
                            continue

                        found_bad_server = True
                        upstream_directives.append(child)

                        if not parsed_upstream_host.endswith(tuple(self.local_suffixes)):
                            severity = gixy.severity.MEDIUM

        if not found_upstream and '$' in directive.args[0]: # https://host/$1 is OK, as long as 'host' is not an 'upstream'.
            return

        if found_upstream and not found_bad_server:
            return

        if not found_upstream:
            if not parsed_host.endswith(tuple(self.local_suffixes)):
                severity = gixy.severity.MEDIUM

        self.add_issue(
            severity=severity,
            directive=[directive] + upstream_directives,
            reason="The proxy_pass directive should use a variable for the hostname.",
        )
