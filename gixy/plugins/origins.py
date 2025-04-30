import re
import logging
import gixy
from gixy.plugins.plugin import Plugin
from gixy.core.regexp import Regexp
from urllib.parse import urlunparse, urlparse, urljoin

LOG = logging.getLogger(__name__)


class origins(Plugin):
    r"""
    Insecure example:
        if ($http_referer !~ "^https?://([^/]+metrika.*yandex\.ru/"){
            add_header X-Frame-Options SAMEORIGIN;
        }
    """
    summary = 'Validation regex for "origin" or "referrer" matches untrusted domain.'
    severity = gixy.severity.MEDIUM
    description = 'Improve the regular expression to match only trusted referrers.'
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/origins.md'
    directives = ['if']
    options = {
        'domains': ['*'],
        'https_only': False
    }

    def __init__(self, config):
        super(origins, self).__init__(config)
        if self.config.get('domains') and self.config.get('domains')[0] and self.config.get('domains')[0] != '*':
            domains = '|'.join(re.escape(d) for d in self.config.get('domains'))

        self.https_only = True if self.config.get('https_only') else False

    def extract_url(self, url):
        extracted_url = urlparse(url)
        fixed_url = urljoin(f'{extracted_url.scheme}://{extracted_url.netloc}', extracted_url.path) # path cannot have multiple `//`, or `..`.
        fixed_parsed = urlparse(fixed_url)
        return extracted_url._replace(path=fixed_parsed.path)

    def check_diff_url(self, url1, url2):
        extracted_url1 = urlparse(url)
        extracted_url2 = urlparse(url)
        return extracted_url1.netloc == extracted_url2.netloc

    def audit(self, directive):
        if directive.operand not in ['~', '~*', '!~', '!~*']:
            # Not regexp
            return

        if directive.variable not in ['$http_referer', '$http_origin']:
            # Not interesting
            return

        invalid_referers = set()
        invalid_origins = set()
        regexp = Regexp(directive.value, case_sensitive=(directive.operand in ['~', '!~']))
        for value in regexp.generate('/', anchored=True):
            extracted_domain = value

            print(extracted_domain, directive.value)

            start_anchor = end_anchor = False
            if extracted_domain.startswith('^'):
                start_anchor = True
                extracted_domain = extracted_domain[1:]
            if extracted_domain.endswith('$'):
                end_anchor = True
                extracted_domain = extracted_domain[:-1]

            try:
                extracted_url = self.extract_url(extracted_domain)
            except ValueError:
                continue
            print(start_anchor, end_anchor, extracted_url)
            if extracted_url.netloc == '':
                # google.com
                # google.com/something
                # ^google.com
                # ^google.com/something
                # google.com$
                # google.com/something$
                # ^google.com$
                # ^google.com/something$
                if directive.variable == '$http_origin':
                    severity = gixy.severity.HIGH
                    reason = f'Regex matches incomplete string "{extracted_domain}"'
                    self.add_issue(directive=directive, reason=reason, severity=severity)
                else:
                    severity = gixy.severity.MEDIUM
                    reason = f'Regex matches incomplete string "{extracted_domain}"'
                    self.add_issue(directive=directive, reason=reason, severity=severity)

                return

            if self.https_only and extracted_url.scheme != 'https':
                continue # XXX: Missing https
            elif extracted_url.scheme != 'http' and extracted_url.scheme != 'https':
                continue # XXX: Invalid scheme
            if directive.variable == '$http_origin':
                if extracted_url.path != '':
                    continue # XXX: Must be empty path

                if start_anchor:
                    if not end_anchor:
                        # ^https://google.com
                        invalid_origins.add(f'{extracted_url.scheme}://{extracted_url.netloc}.evil.com')
                    else:
                        # XXX: Need to handle ^https://gogle.comasdasd.com$ somehow....?
                        # ^https://google.com$
                        pass
                else:
                    if not end_anchor:
                        # https://google.com
                        invalid_origins.add(f'{extracted_url.scheme}://{extracted_url.netloc}.evil.com')
                    else:
                        pass
                        # XXX: Need to handle ^https://gogle.comasdasd.com$ somehow....?
                        # https://google.com$
            elif directive.variable == '$http_referer':
                reparsed_url = urlunparse(extracted_url)
                if start_anchor:
                    if not end_anchor:
                        # ^https://google.com/something <- not vuln
                        # ^https://google.com <- vuln
                        if extracted_url.path == '':
                            invalid_referers.add(reparsed_url + '.evil.com')
                    else:
                        # ^https://google.com/something$
                        # ^https://google.com$
                        # XXX: Need to handle ^https://gogle.comasdasd.com$ somehow....? Try to add `evil.com` at end and see if reparsed_url still matches the regex?
                        pass
                else:
                    if not end_anchor:
                        # https://google.com
                        # https://google.com/something
                        if extracted_url.path == '':
                            invalid_referers.add(reparsed_url + '.evil.com')
                        else:
                            invalid_referers.add('http://evil.com/?' + reparsed_url)
                    else:
                        # https://google.com$
                        # https://google.com/something$
                        invalid_referers.add('http://evil.com/?' + reparsed_url)


        if invalid_referers or invalid_origins:
            if directive.variable == '$http_origin':
                name = 'origin'
                invalids = '", "'.join(invalid_origins)
            else:
                name = 'referrer'
                invalids = '", "'.join(invalid_referers)
            severity = gixy.severity.HIGH if name == 'origin' else gixy.severity.MEDIUM
            reason = 'Regex matches "{value}" as a valid {name}.'.format(value=invalids, name=name)
            self.add_issue(directive=directive, reason=reason, severity=severity)







