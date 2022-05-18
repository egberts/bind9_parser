#!/usr/bin/env python3

#
#  This effort attempts to track and compile a dict/list label outside of its
#      'key' (or 'view') parser block.
#
#  What is expected is:
#
#    result = {
#        'keys' : [
#          { 'key_id': 'first_key_disappeared' },
#          { 'key_id': 'second_key' },
#        ],
#        'views' : [
#            {
#                'zones': [
#                    {'zone_name': 'first_zone'},
#                    {'zone_name': 'second_zone'},
#                    {'zone_name': 'third_zone'},
#                ]
#                'view_name': 'first_view'},   # ordering matters here
#            },
#            {'view_name': 'second_view'},   # ordering matters here
#                'zones': [
#                    {'zone_name': 'fourth_zone'},
#                ]
#                'view_name': 'first_view'},   # ordering matters here
#            }
#        ]
#
#  Note the alternate appearance of 'key'/'view' in 'test_string' variable
#  that forces leaving each of their respective parser element rule.

import pprint
from pyparsing import Keyword, Combine, Literal, ZeroOrMore, Suppress, Word, \
                      Group, CaselessLiteral, alphanums, Char, Optional, \
                      OneOrMore

options_stmt_counter = 0

dquote = Literal('"').setName("'\"'")
squote = Literal("'").setName('"\'"')

lbrack, rbrack, semicolon, slash = map(Suppress, '{};/')

isc_boolean = (
        CaselessLiteral('yes')
        | CaselessLiteral('no')
        | Literal('1')
        | Literal('0')
        | CaselessLiteral('True')
        | CaselessLiteral('False')
)
isc_boolean.setName('<boolean>')

charset_key_id_base = alphanums + '_-'

key_id_base = Word(charset_key_id_base, max=62)

key_id = (
        key_id_base
)('key_id')
key_id.setName('<key_id>')

charset_keysecret_base = alphanums + '+/='

keysecret_base = Word(charset_keysecret_base, max=32767)
key_secret = (
        keysecret_base
)('key_secret')
key_secret.setName('<secret_string>')

rr_class_in = CaselessLiteral('IN')

rr_class_set = (
    rr_class_in
)('rr_class')
rr_class_set.setName('<rr_class>')

domain_charset_alphanums_dash_underscore = alphanums + '_-'

domain_generic_label = Word(domain_charset_alphanums_dash_underscore, min=1, max=63)

domain_generic_fqdn = Combine(
    domain_generic_label
    + ZeroOrMore(
        Literal('.')
        + domain_generic_label
    )
    + Optional(Char('.'))
)
domain_generic_fqdn.setName('<generic-fqdn>')
domain_generic_fqdn.setResultsName('domain_name')

rr_domain_name = Combine(
    domain_generic_fqdn
    + Optional(Literal('.'))
)
rr_domain_name.setName('<rr_domain_name>')

charset_acl_name_base = alphanums + '_-'  # no semicolon nor curly braces allowed
charset_view_name_base = alphanums + '_-' # no semicolon nor curly braces allowed

view_name_base = Word(charset_acl_name_base, max=64)
view_name_base.setName('<view-name-base>')


view_name = (
        view_name_base(None)
)('view_name')
view_name.setName('<view-name>')

charset_filename_base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-.:?@[\\]^_`|~="
charset_filename_base_quotable = charset_filename_base + ';' + '{}'

# only if quoted, can have a space character in its filename
charset_filename_has_dquote = charset_filename_base_quotable + '" '
charset_filename_has_squote = charset_filename_base_quotable + "' "

pathname_base_dquote = Word(charset_filename_has_squote + '/')
pathname_base_squote = Word(charset_filename_has_dquote + '/')

quoted_path_name = (
    (
        Combine(
            dquote
            + pathname_base_dquote
            + dquote
        )
        ^ Combine(
            squote
            + pathname_base_squote
            + squote
        )
    )('quoted_path_name')
)
quoted_path_name.setName('<quoted_path_name>')

charset_zone_name_base = alphanums + '_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon nor curly braces allowed

zone_name_base = Word(charset_zone_name_base)('zone_name')
zone_name_base.setName('<zone-name-unquoted>')


zone_name = (
        zone_name_base
)('zone_name')
zone_name.setName('<zone_name>')

options_stmt_directory = (
    Keyword('directory').suppress()
    - quoted_path_name('directory')
    + semicolon
)

options_statements_set = (
    options_stmt_directory  # reduced to just one option statement
)

options_statements_series = (
    ZeroOrMore(
        options_statements_set
    )
)

options_all_statements_set = (
        options_statements_set  # reduced to just one option set
)


options_all_statements_series = (
    ZeroOrMore(
        (
            options_all_statements_set
        )
    )('')
)('')


def counter_options(strg, loc, toks):
    global options_stmt_counter
    options_stmt_counter = options_stmt_counter + 1


clause_stmt_options = (
    Keyword('options').setParseAction(counter_options).suppress()
    - Group(
        lbrack
        - options_all_statements_series
        + rbrack
    )('')
    + semicolon
)('options')
clause_stmt_options.setName('options { <options-statement>; ... };')

# key <key-name> { };
clause_stmt_key_standalone = (
    Keyword('key').suppress()
    - Group(
        key_id('key_id')
        + lbrack
        + rbrack
    )('key*')
    + semicolon
)

# {0-*} statement
clause_stmt_key_series = (
    ZeroOrMore(
        clause_stmt_key_standalone
    )('keys*')
)
clause_stmt_key_series.setName('key <key-name> { algorithm <string>; secret <key-secret>; };')


clause_stmt_zone_standalone = (
    Keyword('zone').suppress()
    - Group(
        zone_name('zone_name')
        - Optional(rr_domain_name)
        - lbrack
        + rbrack
    )('zones*')
    + semicolon
)('')

clause_stmt_zone_series = (
    OneOrMore(
        Group(clause_stmt_zone_standalone)('')
    )('all_zones2*')
)('all_zones1*')


view_statements_set = (
    clause_stmt_zone_standalone  # reduced to only one view statement
)

view_statements_series = ZeroOrMore(view_statements_set)

view_all_statements_set = (
        view_statements_set  # reduced to only one view set
)

view_all_statements_series = ZeroOrMore(view_all_statements_set)

clause_stmt_view_standalone = (
    Keyword('view').suppress()
    - Group(
        view_name('view_name')
        - Optional(rr_class_set('rr_class'))
        - Group(
            lbrack
            + view_all_statements_series
            + rbrack
        )('view*')
    )('views*')
    + semicolon
)('')

clause_stmt_view_series = (
    ZeroOrMore(
            clause_stmt_view_standalone
    )('all_views1*')
)('all_views0*')


optional_clause_stmt_set = (
        clause_stmt_view_standalone
        | clause_stmt_key_standalone
        | clause_stmt_zone_standalone('zone_clause*')
)

optional_clause_stmt_series = (
    OneOrMore(
        optional_clause_stmt_set
    )
)

mandatory_clause_stmt_set = clause_stmt_options

# TODO: Unable to enforce mixed mode 1-* and 1-1 clauses (external logic required here?)
# TODO: BUG https://github.com/pyparsing/pyparsing/issues/167

# clause_statements: Bind9 master Pyparsing element
clause_statements = ZeroOrMore(
    optional_clause_stmt_set
    | mandatory_clause_stmt_set
    | optional_clause_stmt_set
)


test_string = """
key first_key_disappeared { };

view first_view_disappeared {
    zone first_zone_disappeared { };
    zone second_zone_disappeared { };
    zone third_zone_disappeared { };
    };

key second_key { };

view second_view {
    zone fourth_zone { };
    };

key third_key { };

key fourth_key { };

view third_view {
    zone fifth_zone { };
    zone sixth_zone { };
    zone seventh_zone { };
    };

view fourth_view {
    zone eigth_zone { };
    };

key fifth_key { };
"""

# pp = pprint.PrettyPrinter(width=4, compact=True, indent=4)
pp = pprint.PrettyPrinter(compact=False, indent=2)

result = clause_statements.parseString(test_string, parseAll=True)
print("\nresult:", result)
print("\nresult.asDict():", result.asDict())
print("\nPretty(result.asDict():")
pp.pprint(result.asDict())

expected = { 'key': [ {'key_id': 'first_key_disappeared'},
           {'key_id': 'second_key'},
           {'key_id': 'third_key'},
           {'key_id': 'fourth_key'},
           {'key_id': 'fifth_key'}],
  'views': [ { 'view': [ { 'zones': [ {'zone_name': 'first_zone_disappeared'},
                                      {'zone_name': 'second_zone_disappeared'},
                                      { 'zone_name': 'third_zone_disappeared'}]}],
               'view_name': 'first_view_disappeared'},
             { 'view': [{'zones': [{'zone_name': 'fourth_zone'}]}],
               'view_name': 'second_view'},
             { 'view': [ { 'zones': [ {'zone_name': 'fifth_zone'},
                                      {'zone_name': 'sixth_zone'},
                                      {'zone_name': 'seventh_zone'}]}],
               'view_name': 'third_view'},
             { 'view': [{'zones': [{'zone_name': 'eigth_zone'}]}],
               'view_name': 'fourth_view'}]}

if expected != result.asDict():
    print("Did not match expectation")
    print("Expected:")
    pp.pprint(expected)
else:
    print("Expectation matched.")
