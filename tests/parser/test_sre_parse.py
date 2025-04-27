import pytest
import gixy.core.sre_parse.sre_parse as sre_parse

def test_pcre_verb_removal():
    config = "(*ANYCRLF)/(?P<target>.+?)$"

    # (*ANYCRLF) should be stripped by the parser
    expected = [
        ('literal', 47), ('subpattern', (1, [('min_repeat', (1, 4294967295, [('any', None)]))])), ('at', 'at_end')
    ]

    assert_config(config, expected)


def test_incomplete_pcre_verb():
    config = "(*ANYCRLF"

    # (*ANYCRLF) should be stripped by the parser
    expected = "unterminated PCRE extension"

    assert_config(config, expected)


def assert_config(config, expected):
    try:
        actual = sre_parse.parse(config)
    except sre_parse.error as e:
        actual = str(e)

    assert repr(actual) == repr(expected)
