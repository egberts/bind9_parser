#!/usr/bin/env python3

from pyparsing import Char, Group, Optional, Word, alphanums

def parse_me(parse_element, pattern, expected_pass):
    result = parse_element.parseString(pattern, parseAll=True)
    print('result:', result.asDict())
    return result.asDict()

def convertExclamation(s, l, toks):
    if len(toks[0]):
        for what in toks[0]:
            if '!' == what:
                return True
            else:
                return False
    else:
        return False

exclamation = Char('!')

find_pattern = Group(
    Group(
        Optional(exclamation)
    )('not').setParseAction(convertExclamation)
    + Word(alphanums + '_-/:.')('addr')
)('find_pattern')

parse_me(find_pattern, 'a', True)
parse_me(find_pattern, '! a', True)
