import re
import gixy
from gixy.plugins.plugin import Plugin
from gixy.core.regexp import Regexp
from urllib.parse import urlparse
from publicsuffixlist import PublicSuffixList

_PSL = PublicSuffixList()

class origins(Plugin):
    r"""
    Insecure examples:
        # Insecure referer, allows https://metrika-hacked-yandex.ru/
        if ($http_referer !~ "^https://([^/])+metrika.*yandex\.ru/") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Invalid header, origin cannot contain a path
        if ($http_origin !~ "^https://yandex\.ru/$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Invalid (and insecure) header, 'referrer' is the wrong spelling.
        if ($http_referrer !~ "^https://yandex\.ru/") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Insecure origin header, allows https://sub-yandex.ru
        if ($http_origin !~ "^https://sub.yandex.ru$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Insecure origin header, allows http://sub.yandex.ru (when using --origins-https-only True)
        if ($http_origin !~ "^https?://sub\.yandex\.ru$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Insecure origin header, allows https://yahoo\.com (when using --origins-domains yandex.com)
        if ($http_origin !~ "^https://yahoo\.com$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
    """
    summary = 'Validation regex for "origin" or "referer" matches untrusted domain or invalid value.'
    severity_invalid_header = gixy.severity.LOW
    severity_insecure_referer = gixy.severity.MEDIUM
    severity_insecure_origin = gixy.severity.HIGH
    description = 'Improve the regular expression to match only correct and trusted referers and origins.'
    help_url = 'https://github.com/dvershinin/gixy/blob/master/docs/en/plugins/origins.md'
    directives = ['if']
    options = {
        'domains': ['*'],
        'https_only': False,
        'lower_hostname': True
    }

    def __init__(self, config):
        super(origins, self).__init__(config)
        self.psl = _PSL

        self.directive_type = None
        self.insecure_set = set()
        self.invalid_set = set()

        self.allowed_domains = None
        domains = self.config.get('domains')
        if domains and domains[0] and domains[0] != '*':
            self.allowed_domains = tuple(domains)

        self.https_only = bool(self.config.get('https_only'))
        self.lower_hostname = bool(self.config.get('lower_hostname'))
        self.lower_hostname_pattern = re.compile(r'^[a-z0-9.:\[\]-]+$') # :][ for IPv6

    # Generates and compiles an expression to test against generated->manipulated strings from Regex.generate().
    # Currently unused.
    def compile_nginx_regex(self, nginx_pat, case_sensitive):
        flags = re.IGNORECASE if not case_sensitive else 0
        # strip variables
        np = re.sub(r'(?<!\\)\$(?=\w)', r'\$', nginx_pat)
        # look for ^(?flags)
        m = re.match(r'^\^(\(\?[imxs]+\))', np)
        if m:
            inline_flags = m.group(1)           # e.g. '(?i)'
            rest         = np[m.end():]  # everything after the flags
            python_pat   = f'{inline_flags}^{rest}'
            return re.compile(python_pat, flags)
        else:
            # no inline-global flags to hoist
            return re.compile(np, flags)

    def same_origin(self, i, j):
        if not i or not j:
            return False

        if i == j:
            return True

        return self.psl.privatesuffix(i.strip('.')) == self.psl.privatesuffix(j.strip('.')) != None

    def parse_url(self, url):
        try:
            parsed_url = urlparse(url)
            if not parsed_url.hostname or not parsed_url.scheme:
                # Attempt to fixup the url for the second pass
                # e.g. 'domain.com$', 'google.com/lol', '/lol$'
                # should become 'https://def.comdomain.com', 'https://def.comgoogle.com/lol', and 'https://def.comabc.com/lol'.
                if url[0] == '/':
                    url = 'abc.com' + url
                if '://' not in url:
                    url = 'https://def.com' + url
                self.insecure_set.add(url)
                return

            if self.https_only and parsed_url.scheme != 'https':
                self.insecure_set.add(url)
                return

            if parsed_url.scheme not in {'http', 'https'}:
                self.insecure_set.add(url)
                return

            return parsed_url
        except:
            self.invalid_set.add(url)

    def audit(self, directive):
        self.directive_type = directive.variable

        if directive.operand not in ['~', '~*', '!~', '!~*']:
            return

        if self.directive_type not in ['$http_referer', '$http_origin', '$http_referrer']:
            return

        if self.directive_type == '$http_referrer':
            reason = 'Incorrect header "$http_referrer". Use "$http_referer".'
            self.add_issue(directive=directive, reason=reason, severity=severity_insecure_origin)
            return

        self.insecure_set = set()
        self.invalid_set = set()

        case_sensitive = directive.operand in ['~', '!~']
        name = self.directive_type.split('_')[1]
        severity = severity_insecure_origin if name == 'origin' else severity_insecure_referer

        regexp = Regexp(directive.value, case_sensitive=case_sensitive)
        for candidate_match in regexp.generate('`', anchored=True, max_repeat=5): # Replace matching groups with '`' (which should not be in a real URL as it should be url-encoded).

            # Decode to punycode if needed.
            candidate_match = candidate_match.encode('idna').decode()

            # Replace any unexpected characters from the generated expressions.
            # We do this because Regexp.generate() may replace sequences with  \r, \t, \n, etc, if '`' isn't allowed in a capture group.
            # This means we are violating the regex.
            # This is a known problem, but we decide to ignore it.
            # XXX: Should we use urllib.parse.quote?
            candidate_match = re.sub(r'[^A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=`^%"]', '`', candidate_match)

            # Strip anchors and parse the URL.
            # ^https://example\.com$ -> https://example.com
            base_mutant_raw = candidate_match.lstrip('^').rstrip('$')
            base_mutant_parsed = self.parse_url(base_mutant_raw)
            if not base_mutant_parsed:
                continue
            base_hostname = base_mutant_parsed.hostname

            # Strip begin-anchor. If an end-anchor exists, strip it; if not, append '.evil.com'.
            # ^https://example\.com -> https://example.com.evil.com
            suffix_mutant_raw = candidate_match.lstrip('^')
            if suffix_mutant_raw.endswith('$'):
                suffix_mutant_raw = suffix_mutant_raw.rstrip('$')
            else:
                suffix_mutant_raw += '.evil.com'
            suffix_mutant_parsed = self.parse_url(suffix_mutant_raw)
            if not suffix_mutant_parsed:
                continue
            suffix_hostname = suffix_mutant_parsed.hostname
            # Check whether the base_hostname and suffix_hostname parsed domains are off-domain.
            if not self.same_origin(base_hostname, suffix_hostname):
                self.insecure_set.add(suffix_mutant_raw)
                continue

            # Strip end-anchor. If a begin-anchor exists, strip it; if not, prepend either 'http://evil.com/?' or 'http://evil.com' depending on the the directive.
            # https://example\.com$ -> http://evil.com/?https://example.com
            # https://example\.com$ -> http://evil.comhttps://example.com
            prefix_mutant_raw = candidate_match.rstrip('$')
            if prefix_mutant_raw.startswith('^'):
                prefix_mutant_raw = prefix_mutant_raw.lstrip('^')
            else:
                if name == 'referer':
                    prefix_mutant_raw = 'http://evil.com/?' + prefix_mutant_raw
                else:
                    # Do NOT remove any '://' from the URL.
                    # We want to create http://evil.comhttp://example.com which has the path '//example', which will be reported as invalid, not insecure.
                    # Since we can actually form a valid origin (no path allowed), we WANT it to report as invalid.
                    prefix_mutant_raw = 'http://evil.com' + prefix_mutant_raw
            prefix_mutant_parsed = self.parse_url(prefix_mutant_raw)
            if not prefix_mutant_parsed:
                continue
            prefix_hostname = prefix_mutant_parsed.hostname
            # Check again whether the result is off-domain.
            if not self.same_origin(base_hostname, prefix_hostname):
                self.insecure_set.add(prefix_mutant_raw)
                continue

            # Replace all '`' characters with a,b,c.
            # Unfortunately, this means that if a capture group does not allow '`', some other character will be used which invalidates all of the following tests.
            # Likewise, if the capture group doesn't allow a,b,c, then we are violating the regex.
            # This is a known problem, but we decide to ignore it.
            base_hostname_filled = base_hostname.replace('`', 'a')
            suffix_hostname_filled = suffix_hostname.replace('`', 'b')
            prefix_hostname_filled = prefix_hostname.replace('`', 'c')

            base_mutant_raw_filled = base_mutant_raw.replace('`', 'a')
            suffix_mutant_raw_filled = suffix_mutant_raw.replace('`', 'b')
            prefix_mutant_raw_filled = prefix_mutant_raw.replace('`', 'c')

            # Check whether replacing each of the '`' characters with a,b,c results in off-domains.
            if not self.same_origin(base_hostname_filled, base_hostname_filled): # Sanity check
                self.insecure_set.add(base_mutant_raw_filled)
                continue

            if not self.same_origin(base_hostname_filled, suffix_hostname_filled):
                self.insecure_set.add(suffix_mutant_raw_filled)
                continue

            # XXX: Is this third one necessary? Changes for groups should be see across first and second already I think?
            if not self.same_origin(base_hostname_filled, prefix_hostname_filled):
                self.insecure_set.add(prefix_mutant_raw_filled)
                continue

            # Ensure that each of base domains are allowed, if specified.
            if self.allowed_domains:
                if not any(
                        self.same_origin(base_hostname_filled, d)
                        for d in self.allowed_domains):
                    self.insecure_set.add(base_mutant_raw_filled)
                    continue

                if not any(
                        self.same_origin(suffix_hostname_filled, d)
                        for d in self.allowed_domains):
                    self.insecure_set.add(suffix_mutant_raw_filled)
                    continue
                if not any(
                        self.same_origin(prefix_hostname_filled, d)
                        for d in self.allowed_domains):
                    self.insecure_set.add(prefix_mutant_raw_filled)
                    continue

            # Hostnames should be lowercase (no browser supports uppercase). urlparse.netloc preserves case.
            if self.lower_hostname:
                if not self.lower_hostname_pattern.fullmatch(base_mutant_parsed.netloc.replace('`', 'a')):
                    self.invalid_set.add(base_mutant_raw_filled)
                    continue
                if not self.lower_hostname_pattern.fullmatch(suffix_mutant_parsed.netloc.replace('`', 'b')):
                    self.invalid_set.add(suffix_mutant_raw_filled)
                    continue
                if not self.lower_hostname_pattern.fullmatch(prefix_mutant_parsed.netloc.replace('`', 'c')):
                    self.invalid_set.add(prefix_mutant_raw_filled)
                    continue

            # Origin has a strict format requirement of nothing other than <scheme>://<hostname>[:port]
            if name == 'origin':
                if len(base_mutant_parsed.path + base_mutant_parsed.params + base_mutant_parsed.query + base_mutant_parsed.fragment) > 0:
                    self.invalid_set.add(base_mutant_raw_filled)
                    continue
                if len(suffix_mutant_parsed.path + suffix_mutant_parsed.params + suffix_mutant_parsed.query + suffix_mutant_parsed.fragment) > 0:
                    self.invalid_set.add(suffix_mutant_raw_filled)
                    continue
                if len(prefix_mutant_parsed.path + prefix_mutant_parsed.params + prefix_mutant_parsed.query + prefix_mutant_parsed.fragment) > 0:
                    self.invalid_set.add(prefix_mutant_raw_filled)
                    continue

        if self.insecure_set:
            for url in self.insecure_set.copy():
                try:
                    # Second pass of parsing URL. Try to move any invalid URLs to invalid_set.
                    parsed_url = urlparse(url)
                    if not parsed_url.scheme or not parsed_url.hostname:
                        self.invalid_set.add(url)
                        self.insecure_set.remove(url)

                    if name == 'origin':
                        if len(parsed_url.path + parsed_url.params + parsed_url.query + parsed_url.fragment) > 0:
                            self.invalid_set.add(url)
                            self.insecure_set.remove(url)
                except:
                    continue
            if self.insecure_set:
                invalids = '", "'.join(self.insecure_set).replace('`', 'a')
                reason = 'Regex matches insecure "{value}" as a valid {name}.'.format(value=invalids, name=name)
                self.add_issue(directive=directive, reason=reason, severity=severity)

        if self.invalid_set:
            invalids = '", "'.join(self.invalid_set).replace('`', 'a')
            reason = 'Regex matches invalid "{value}" as a valid {name}.'.format(value=invalids, name=name)

            if name == 'origin':
                reason += ' Origin headers must in the format of <scheme>://<hostname>[:port]. No path can be specified.'
            else:
                reason += ' Referer headers should use absolute URLs including a scheme and hostname.'
            if self.lower_hostname:
                reason += ' All characters in the scheme and hostname should be lowercase.'

            self.add_issue(directive=directive, reason=reason, severity=severity_invalid_header)
