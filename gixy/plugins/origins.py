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

    def fixup_evil(self, url):
        parts = url.split('://')
        if len(parts) >= 3:
            return "http://evil.com" + '://'.join(parts[2:])
        else:
            return url

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

    def audit(self, directive):
        if directive.operand not in ['~', '~*', '!~', '!~*']:
            # Not regexp
            return

        if directive.variable not in ['$http_referer', '$http_origin']:
            # Not interesting
            return

        insecure_referers = set()
        insecure_origins = set()
        invalid_origins = set()
        invalid_referers = set()
        regexp = Regexp(directive.value, case_sensitive=(directive.operand in ['~', '!~']))
        for value in regexp.generate('`', anchored=True, max_repeat=30):
            # We first use the ` character as a magic value to determine whether there's any unescaped matching-characters in the hostname (*, ?, . etc)
            # If there is a ` character in the private suffix of the hostname, then it's vulnerable no matter what (since it can be replaced with any character).
            # We simply hope that there's no other ` characters elsewhere in the expression (and, why would there be? It's not valid in a hostname, scheme, or hostname, and unlikely in a path name)
            regex_combo = value

            # Follows the old logic
            start_anchor = end_anchor = False
            if regex_combo.startswith('^'):
                start_anchor = True
                regex_combo = regex_combo[1:]
            else:
                # Do not add path, so we can pick up cases like ~ 'yandex.com', which if we add a path, will turn into:
                # http://evil.com/yandex.com which will be picked up as an invalid origin (due to the path)
                # XXX: if ($http_origin !~ 'https://google.*com$') {} gets clobbered to http://evil.comhttps://google.*com
                regex_combo = 'http://evil.com' + regex_combo
                regex_combo = self.fixup_evil(regex_combo)

            if regex_combo.endswith('$'):
                end_anchor = True
                regex_combo = regex_combo[:-1]
            else:
                regex_combo += '.evil.com'

            # Replace any unexpected characters from the generated expressions.
            # We do this because Regexp.generate() may replace sequences with non-ascii, or even \r, \t, \n.
            # Not really needed due to the '`' character usage anymore, but will leave it anyways.
            regex_combo = re.sub(r"[^A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]", "`", regex_combo)

            # Now, try to parse the URL that was generated.
            try:
                # Will shorten any paths that are in the form `../` or `//`.
                extracted_url = self.extract_url(regex_combo)
            except ValueError:
                if directive.variable == '$http_origin':
                    invalid_origins.add(regex_combo)
                else:
                    invalid_referers.add(regex_combo)
                continue

            # Skip checks of expressions with port numbers for now.
            # Old logic didn't work with this anyways.
            try:
                if extracted_url.port:
                    continue
            except ValueError:
                continue

            # If no hostname can be found or it's empty, then it is an incomplete expression, for example:
            # 1) Invalid, e.g. ^google.com$ -- referer and origin can not be without scheme, or
            # 2) Valid, but too permissive, e.g. google.com -- will match https://google.com but also https://something-google.com-something.com
            # XXX: The replacements with http://evil.com and evil.com here may be invalid, because the matching group may disallow those characters! However, the old logic also suffered from similar problems.
            if not extracted_url.hostname or extracted_url.hostname == '':
                if '`' in regex_combo:
                    regex_combo = regex_combo.replace('`', 'http://evil.com', 1)
                    regex_combo = self.fixup_evil(regex_combo)
                    regex_combo = '.evil.com'.join(regex_combo.rsplit('`', 1))
                    regex_combo = regex_combo.replace('`', '.com')
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue

            # If there is a matching group in the private suffix of the hostname, then the header can be bypassed
            if '`' in extracted_url.hostname:
                before_extracted_hostname = extracted_url.hostname
                regex_combo = '.evil.com'.join(regex_combo.rsplit('`'*20, 1))
                regex_combo = regex_combo.replace('`', 'a')
                extracted_url = self.extract_url(regex_combo)
                if self.psl.privatesuffix(extracted_url.hostname) != self.psl.privatesuffix(before_extracted_hostname):
                    # e.g. google.com -> googleacom, google.com.au -> googleacomaau
                    # and google.*com -> googleaaaaaaaaaa.evil.comcom
                    # but NOT 123.google.com -> 1234.google.com
                    if directive.variable == '$http_origin':
                        insecure_origins.add(regex_combo)
                    else:
                        insecure_referers.add(regex_combo)
                    continue

            # Effectively follows the old logic
            # 'evil.com' check ensures that if we've prepended http://evil.com/, we don't consider that as an https violation (picked up later as a new domain violation)
            if self.https_only and extracted_url.scheme != 'https' and not extracted_url.hostname.startswith('evil.com'):
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue
            elif extracted_url.scheme != 'http' and extracted_url.scheme != 'https':
                if directive.variable == '$http_origin':
                    invalid_origins.add(regex_combo)
                else:
                    invalid_referers.add(regex_combo)
                continue

            # Effectively follows the old logic.
            # Ensure that the hostname extracted is allowlisted, if applicable.
            if self.allowed_domains:
                if not extracted_url.hostname.endswith(tuple(self.allowed_domains)):
                    if directive.variable == '$http_origin':
                        insecure_origins.add(regex_combo)
                    else:
                        insecure_referers.add(regex_combo)
                    continue

            # Effectively follows the old logic. If the hostname starts or ends with evil.com, we've jumped to a new domain.
            # e.g. google.com.evil.com or evil.comgoogle.com
            # Also picks up where evil.com is the new domain.
            if extracted_url.hostname.endswith('evil.com') or extracted_url.hostname.startswith('evil.com'):
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue

            # Effectively follows the old logic (regex would match yandex.com but not yandex)
            # This was mostly useful in the case of `yandex.com` becoming `yandex/com`, or `yandex.com.au` becoming `yandex/com/au`.
            # But that is now dealt with differently. But this now picks up, for e.g.
            # google.*com -> googlebbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            if '.' not in extracted_url.hostname:
                if directive.variable == '$http_origin':
                    insecure_origins.add(regex_combo)
                else:
                    insecure_referers.add(regex_combo)
                continue

            # Finally, if it's an origin and it has a path,params,query, or fregmanet, it's invalid (must be <scheme>://<host> and optional :<port>)
            # Or if it's a referer, it must have at least a scheme and host, but this has already been handled.
            if directive.variable == '$http_origin':
                if extracted_url.path != '' or extracted_url.params != '' or extracted_url.query != '' or extracted_url.fragment != '' or extracted_url.scheme not in {'http', 'https'}:
                    invalid_origins.add(regex_combo)
                    continue

            if self.lower_hostname:
                uc_pattern = re.compile(r'^[A-Za-z0-9_.:-]+$')
                if not uc_pattern.fullmatch(extracted_url.netloc):
                    if directive.variable == '$http_origin':
                        invalid_origins.add(regex_combo)
                    else:
                        invalid_referers.add(regex_combo)
                    continue


            print("whatever: ", regex_combo, extracted_url, directive.value)
            continue


        # Filter out any invalid (but not insecure) origins
        for origin in insecure_origins.copy():
            try:
                extracted_url = self.extract_url(origin)
                if extracted_url.scheme == '' or not extracted_url.hostname or extracted_url.hostname == '' or extracted_url.scheme not in {'http', 'https'}:
                    invalid_origins.add(origin)
                    insecure_origins.remove(origin)
                elif extracted_url.path != '' or extracted_url.params != '' or extracted_url.query != '' or extracted_url.fragment != '':
                    invalid_origins.add(origin)
                    insecure_origins.remove(origin)
                elif self.lower_hostname:
                    uc_pattern = re.compile(r'^[A-Za-z0-9_.:-]+$')
                    if not uc_pattern.fullmatch(extracted_url.netloc):
                        invalid_origins.add(origin)
                        insecure_origins.remove(origin)
            except ValueError:
                continue

        for referer in insecure_referers.copy():
            try:
                extracted_url = self.extract_url(referer)
                if extracted_url.scheme == '' or not extracted_url.hostname or extracted_url.hostname == '' or extracted_url.scheme not in {'http', 'https'}:
                    invalid_referers.add(referer)
                    insecure_referers.remove(referer)
                elif self.lower_hostname:
                    uc_pattern = re.compile(r'^[A-Za-z0-9_.:-]+$')
                    if not uc_pattern.fullmatch(extracted_url.netloc):
                        invalid_referers.add(referer)
                        insecure_referers.remove(referer)
            except ValueError:
                continue

        if insecure_referers or insecure_origins:
            if directive.variable == '$http_origin':
                name = 'origin'
                invalids = '", "'.join(insecure_origins)
            else:
                name = 'referrer'
                invalids = '", "'.join(insecure_referers)
            severity = gixy.severity.HIGH if name == 'origin' else gixy.severity.MEDIUM
            reason = 'Regex matches "{value}" as a valid {name}.'.format(value=invalids, name=name)
            self.add_issue(directive=directive, reason=reason, severity=severity)

        if invalid_referers or invalid_origins:
            if directive.variable == '$http_origin':
                name = 'origin'
                invalids = '", "'.join(invalid_origins)
                msg = 'Origin headers must in the format of <scheme>://<hostname>.'
            else:
                name = 'referrer'
                invalids = '", "'.join(invalid_referers)
                msg = "Referer headers should use absolute URLs including a scheme and hostname."

            if self.lower_hostname:
                msg += " All characters in the scheme and hostname should be lowercase."
            severity = gixy.severity.LOW
            reason = 'Regex matches the invalid format "{value}" as a valid {name}. {msg}'.format(value=invalids, name=name, msg=msg)
            self.add_issue(directive=directive, reason=reason, severity=severity)
