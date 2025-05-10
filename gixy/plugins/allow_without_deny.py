import gixy
from gixy.plugins.plugin import Plugin


class allow_without_deny(Plugin):
    """
    Bad: allow 127.0.0.1;
    Good: allow 127.0.0.1; deny all;
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
        deny_found = False
        for child in parent.children:
            if child.name == 'deny':
                deny_found = True
                break
        if not deny_found:
            reason = 'You probably want "deny all;" after all the "allow" directives'
            self.add_issue(
                directive=[directive, parent, parent.children[len(parent.children)-1]],
                reason=reason
            )
