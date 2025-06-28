import gixy
from gixy.plugins.plugin import Plugin


class allow_without_deny(Plugin):
    """
    Bad example: allow 127.0.0.1; deny all;
    Good example: allow 127.0.0.1;
    """
    summary = 'Found allow directive(s) without deny in the same context.'
    severity = gixy.severity.HIGH
    description = 'The "allow" directives should be typically accompanied by "deny all;" directive'
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/allow_without_deny.md'
    directives = ['allow']

    def audit(self, directive):
        parent = directive.parent
        if not parent:
            return

        if directive.args == ['all']:
            # example, "allow all" in a nested location which allows access to otherwise forbidden parent location
            return


        for ctx in directive.parents:
            if ctx.name in {'http', 'server', 'location', 'limit_except'}:
                # Any ‘deny’ inside this block (flattened)
                if ctx.some('deny', True):
                    return
                break

        reason = 'You probably want "deny all;" after all the "allow" directives'
        self.add_issue(
            directive=directive,
            reason=reason
        )
