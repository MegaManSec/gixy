import re
import logging
import gixy
from gixy.plugins.plugin import Plugin
from gixy.core.regexp import Regexp
from urllib.parse import urlunparse, urlparse, urljoin
from publicsuffixlist import PublicSuffixList

LOG = logging.getLogger(__name__)


class origins(Plugin):
    r"""
    Insecure example:
        if ($http_referer !~ "^https?://([^/]+metrika.*yandex\.ru/"){
            add_header X-Frame-Options SAMEORIGIN;
        }
    """
    summary = 'Validation regex for "origin" or "referrer" matches untrusted or invalid value.'
    severity = gixy.severity.MEDIUM
    description = 'Improve the regular expression to match only correct and trusted referrers and origins.'
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/origins.md'
    directives = ['if']
    options = {
        'domains': ['*'],
        'https_only': False,
        'lower_hostname': True
    }

    def __init__(self, config):
        super(origins, self).__init__(config)
        self.allowed_domains = None

        domains = self.config.get('domains')
        if domains and domains[0] and domains[0] != '*':
            self.allowed_domains = tuple(domains)

        self.psl = PublicSuffixList()
        self.https_only = True if self.config.get('https_only') else False
        self.lower_hostname = True if self.config.get('lower_hostname') else False

    def extract_url(self, url):
        extracted_url = urlparse(url)
        # urljoin doesn't work as I would expect:
        # > urljoin('http://one', '//two')
        # 'http://two'
        while '//' in extracted_url.path:
            extracted_url = extracted_url._replace(path=extracted_url.path.replace('//', '/'))
        fixed_url = urljoin(f'{extracted_url.scheme}://{extracted_url.hostname}', extracted_url.path) # path cannot have multiple `//`, or `..`.
        fixed_parsed = urlparse(fixed_url)
        return extracted_url._replace(path=fixed_parsed.path)

    def compile_nginx_regex(self, nginx_pat):
        # strip variables
        np = re.sub(r'(?<!\\)\$(?=\w)', '\$', nginx_pat)
        # look for ^(?flags)
        m = re.match(r'^\^(\(\?[imxs]+\))', np)
        if m:
            inline_flags = m.group(1)           # e.g. "(?i)"
            rest         = nginx_pat[m.end():]  # everything after the flags
            python_pat   = f"{inline_flags}^{rest}"
            return re.compile(python_pat, re.IGNORECASE)
        else:
            # no inline-global flags to hoist
            return re.compile(np, re.IGNORECASE)

    def audit(self, directive):
        if directive.operand not in ['~', '~*', '!~', '!~*']:
            # Not regexp
            return

        if directive.variable not in ['$http_referer', '$http_origin']:
            # Not interesting
            return

        insecure_referers = set()
        insecure_origins = set()
        regexp = Regexp(directive.value, case_sensitive=(directive.operand in ['~', '!~']))
        for value in regexp.generate('`', anchored=True, max_repeat=5): # Basically generates a valid match for the regex, with any free characters being replaced with ` (up to 30 times)
            # pure_regex_combo: contains an expression which matches the regex, removing the ^ and $ characters (if applicable)
            pure_regex_combo = regex_combo = value

            # regex_combo: contains an expression which matches the regex. If `^` is not at the beginning, prepend it with http://evil.com.
            # The idea is that if we have 'https://google.com$', it becomes 'http://evil.com/https://google.com/, resulting in a hostname change.
            # If `$` is not at the end, append it with `.evil.com`. This is in order to turn `https://google.com` into `https://google.com.evil.com`.

            if regex_combo.startswith('^'):
                regex_combo = regex_combo[1:]
                pure_regex_combo = pure_regex_combo[1:]
            else:
                regex_combo = 'http://evil.com/' + regex_combo

            if regex_combo.endswith('$'):
                regex_combo = regex_combo[:-1]
                pure_regex_combo = pure_regex_combo[:-1]
            else:
                regex_combo += '.evil.com'

            u_uc_pattern = self.compile_nginx_regex(directive.value)

            # The ` character is used to signify that a character group is present, meaning it can be any character.
            # First, we replace the pure/original match's ` characters with 'a'
            pure_regex_combo = pure_regex_combo.replace('`', 'a')
            # Second, we replace the possibly prepended/appended match's ` characters with 'b'
            regex_combo = regex_combo.replace('`', 'b')

            # If the suffix differs between these two, then it's possible to 'break' the origin/referer check.

            try:
                pure_extracted_url = self.extract_url(pure_regex_combo)
                extracted_url = self.extract_url(regex_combo)
            except ValueError:
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue
            if not u_uc_pattern.search(regex_combo):
                print("wtf?", directive.value, u_uc_pattern.pattern, regex_combo)
                insecure_origins.add(regex_combo)
                continue

            if extracted_url.scheme not in {'http', 'https'} or not extracted_url.hostname or extracted_url.hostname == '':
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue

            if pure_extracted_url.scheme not in {'http', 'https'} or not pure_extracted_url.hostname or pure_extracted_url.hostname == '':
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue

            if directive.variable == '$http_origin':
                if extracted_url.path != '' or extracted_url.params != '' or extracted_url.query != '' or extracted_url.fragment != '' or pure_extracted_url.path != '' or pure_extracted_url.params != '' or pure_extracted_url.query != '' or pure_extracted_url.fragment != '':
                    insecure_origins.add(regex_combo)
                    continue

            if self.allowed_domains:
                if not extracted_url.hostname.endswith(tuple(self.allowed_domains)):
                    if directive.variable == '$http_origin':
                        insecure_origins.add(regex_combo)
                    else:
                        insecure_referers.add(regex_combo)
                    continue

            if self.lower_hostname:
                uc_pattern = re.compile(r'^[A-Za-z0-9_.-]+$')
                if not uc_pattern.fullmatch(extracted_url.hostname):
                    if directive.variable == '$http_origin':
                        insecure_origins.add(regex_combo)
                    else:
                        insecure_referers.add(regex_combo)
                    continue

            psl_exu_hostname = self.psl.privatesuffix(extracted_url.hostname)
            psl_pexu_hostname = self.psl.privatesuffix(pure_extracted_url.hostname)

            if psl_exu_hostname != psl_pexu_hostname:
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue

            if psl_exu_hostname is None:
                if extracted_url.hostname != pure_extracted_url.hostname:
                    if directive.variable == '$http_origin':
                        insecure_origins.add(regex_combo)
                    else:
                        insecure_referers.add(regex_combo)
                    continue



        if insecure_referers or insecure_origins:
            if directive.variable == '$http_origin':
                name = 'origin'
                invalids = '", "'.join(insecure_origins)
                msg = 'Origin headers must in the format of <scheme>://<hostname>.'
            else:
                name = 'referrer'
                invalids = '", "'.join(insecure_referers)
                msg = "Referer headers should use absolute URLs including a scheme and hostname."

            if self.lower_hostname:
                msg += " All characters in the scheme and hostname should be lowercase."

            severity = gixy.severity.HIGH if name == 'origin' else gixy.severity.MEDIUM
            reason = 'Regex matches "{value}" as a valid {name}. {msg}'.format(value=invalids, name=name, msg=msg)
            self.add_issue(directive=directive, reason=reason, severity=severity)
