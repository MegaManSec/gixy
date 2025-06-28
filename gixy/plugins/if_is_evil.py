import gixy
from gixy.plugins.plugin import Plugin


class if_is_evil(Plugin):
    """
    Insecure example:
        location /only-one-if {
            set $true 1;
            if ($true) {
                add_header X-First 1; # Bug: not in the response
            }
            if ($true) {
                add_header X-Second 2;
            }
            return 204;
        }
    """
    summary = 'If is Evil... when used in location context.'
    severity = gixy.severity.HIGH
    description = 'Directive "if" has problems when used in location context, in some cases it does not do what you ' \
                  'expect but something completely different instead. In some cases it even segfaults. It is ' \
                  'generally a good idea to avoid it if possible.'
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/if_is_evil.md'
    directives = []

    def audit(self, directive):
        found_if = False
        parent = None
        for parent in directive.parents:
            if parent.name == 'if':
                found_if = True
                break

        # if parent is not "if" break out
        if not found_if:
            return

        # "rewrite ... last" is safe
        if directive.name == 'rewrite' and directive.args[-1] == 'last':
            return

        # "return" is safe too
        if directive.name == 'return':
            return

        for grandparent in parent.parents:
            if grandparent and grandparent.name == 'location':
                reason = 'Directive "{directive}" is not safe to use in "if in location" context'.format(directive=directive.name)
                if directive.name == 'rewrite':
                    reason = 'Directive "rewrite" is only safe to use in "if in location" context when "last" ' \
                    'argument is used'
                self.add_issue(
                    severity=gixy.severity.HIGH,
                    directive=[directive, parent],
                    reason=reason
                )
                break
