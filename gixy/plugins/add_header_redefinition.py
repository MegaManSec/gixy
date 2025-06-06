import gixy
from gixy.plugins.plugin import Plugin


class add_header_redefinition(Plugin):
    """
    Insecure example:
        server {
            add_header X-Content-Type-Options nosniff;
            location / {
                add_header X-Frame-Options DENY;
            }
        }
    """
    summary = 'Nested "add_header" drops parent headers.'
    severity = gixy.severity.LOW
    description = ('"add_header" replaces ALL parent headers. '
                   'See documentation: https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header')
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/addheaderredefinition.md'
    directives = ['server', 'location', 'if']
    options = {'headers': set()}

    def __init__(self, config):
        super(add_header_redefinition, self).__init__(config)
        self.interesting_headers = self.config.get('headers')
        # Define secure headers that should escalate severity
        self.secure_headers = [
            'cache-control',
            'content-security-policy',
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy',
            'permissions-policy',
            'referrer-policy',
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection',
            'expect-ct',
            'pragma',
            'expires',
            'content-disposition'
        ]

    def audit(self, directive):
        if not directive.is_block:
            # Skip all not block directives
            return

        actual_headers = get_headers(directive)
        if not actual_headers:
            return

        for parent in directive.parents:
            parent_headers = get_headers(parent)
            if not parent_headers:
                continue

            diff = parent_headers - actual_headers

            if len(self.interesting_headers):
                diff = diff & self.interesting_headers

            if len(diff):
                self._report_issue(directive, parent, diff)

            break

    def _report_issue(self, current, parent, diff):
        directives = []
        # Add headers from parent level
        directives.extend(parent.find('add_header'))
        # Add headers from the current level
        directives.extend(current.find('add_header'))

        # Check if any dropped header is a secure header
        is_secure_header_dropped = any(header in self.secure_headers for header in diff)

        # Set severity based on whether a secure header was dropped
        issue_severity = gixy.severity.MEDIUM if is_secure_header_dropped else self.severity

        reason = 'Parent headers "{headers}" was dropped in current level'.format(headers='", "'.join(diff))
        self.add_issue(directive=directives, reason=reason, severity=issue_severity)


def get_headers(directive):
    headers = directive.find('add_header')
    if not headers:
        return set()

    return set(map(lambda d: d.header, headers))
