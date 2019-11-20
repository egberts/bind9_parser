#!/usr/bin/env python3

from pyparsing import Char, Group, Optional, Word, alphanums,\
    CaselessLiteral, Literal

def parse_me(parse_element, pattern):
    result = parse_element.parseString(pattern, parseAll=True)
    print('result:', result.asDict())
    return result.asDict()

def convertBoolean(s, l, toks):
    print('toks:', toks)
    if len(toks[0]):
        if (toks[0].lower() == 'true') or (toks[0].lower() == 'yes'):
            return True
        elif (toks[0].lower() == 'false') or (toks[0].lower() == 'no'):
            return False
        if toks[0].isnumeric():
            if int(toks[0]) == 1:
                return True
            elif int(toks[0]) == 0:
                return False
    else:
        return False

isc_boolean = (
    CaselessLiteral('true')
    | CaselessLiteral('false')
    | CaselessLiteral('yes')
    | CaselessLiteral('no')
    | Literal('1')
    | Literal('0')
)

find_pattern = Group(
    Word(alphanums + '_-/:.')('isc_boolean').setParseAction(convertBoolean)
)('find_pattern')

parse_me(find_pattern, 'TRUE')
parse_me(find_pattern, 'True')
parse_me(find_pattern, 'true')
parse_me(find_pattern, 'yes')
parse_me(find_pattern, 'Yes')
parse_me(find_pattern, 'YES')
parse_me(find_pattern, '1')

parse_me(find_pattern, 'FALSE')
parse_me(find_pattern, 'False')
parse_me(find_pattern, 'false')
parse_me(find_pattern, 'no')
parse_me(find_pattern, 'No')
parse_me(find_pattern, 'NO')
parse_me(find_pattern, '0')

parse_me(find_pattern, 'bogus')
parse_me(find_pattern, 'wrong')
parse_me(find_pattern, 'righto')
parse_me(find_pattern, 'yeah')
parse_me(find_pattern, 'nope')
parse_me(find_pattern, 'nah')
parse_me(find_pattern, '12345')
