#!/usr/bin/env python3
"""
File: isc_utils.py

Clause: all

Title: ISC Syntax Utilities

Description: Utility functions for pyparsing of ISC-style
             configuration file

             pe.setName() shall follow ISC Bind9 naming convention

Requires: pyparsing-2.4.3 (Char method)
"""
import copy
import os
import os.path
import errno
import sys
import argparse
from pprint import PrettyPrinter
from pyparsing import Literal, CaselessLiteral, \
    ParseException, ParseSyntaxException, \
    Word, alphanums, Group, Optional, nums, Combine, Char, \
    cppStyleComment, pythonStyleComment, OneOrMore, \
    Suppress, ungroup

UNIX_PIPE_SUPPORT = False
period = Literal('.')
exclamation = Char('!')
exclamation.setName('not')
lbrack, rbrack, semicolon, slash = map(Suppress, '{};/')
dquote = Literal('"').setName("'\"'")
squote = Literal("'").setName('"\'"')
isc_boolean = (
        CaselessLiteral('yes')
        ^ CaselessLiteral('no')
        ^ Literal('1')
        ^ Literal('0')
        ^ CaselessLiteral('True')
        ^ CaselessLiteral('False')
)
isc_boolean.setName('<boolean>')

# alphanums_series = Group(Word(alphanums) + Word(alphanums)) + semicolon
charset_hexnums = '0123456789ABCDEFabcdef'

# isc_file_name has no '/', (but path_name do)
charset_filename_base = "0123456789abcdefghijklmnopqrstuvwxyz" \
                        + "ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-.:?@[\\]^_`|~="
# charset_filename_base is largely printable, but has
#     no double-quote, single-quote, semicolon, curly-braces, nor slash

# no dquote/squote/slash/space
charset_filename_base_quotable = charset_filename_base + ';' + '{}'

# has single-quote, semicolon, and space
charset_filename_has_squote = charset_filename_base_quotable + "' "

# has double-quote, semicolon, and space
charset_filename_has_dquote = charset_filename_base_quotable + '" '

filename_base = Word(charset_filename_base)
filename_base.setName('<printable-chars_has_no_squote_dquote_semicolon_slash_space>')
filename_dquotable = Combine(
    dquote
    + Word(charset_filename_has_squote)
    + dquote
)  # inverse quote types here

filename_squotable = Combine(
    squote
    + Word(charset_filename_has_dquote)
    + squote
)  # inverse quote types here

filename_dquotable.setName('<printable-chars_has_no_dquote_slash>')

isc_file_name = (
        filename_dquotable
        | filename_squotable
        | filename_base
)('filename')
isc_file_name.setName('<file-name>')

pathname_base = Word(charset_filename_base + '/')
pathname_base.setName('<printable-chars_has_no_squote_dquote_semicolon_space>')

# inverse quote types here
pathname_base_dquote = Word(charset_filename_has_squote + '/')
pathname_base_dquote.setName('<printable-chars_has_no_dquote>')

# inverse quote types here
pathname_base_squote = Word(charset_filename_has_dquote + '/')
pathname_base_squote.setName('<printable-chars_has_no_squote>')

path_name = (
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
        ^ pathname_base
    )('path_name')
)
path_name.setName('<path_name>')

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

# dequote/dequotable
dequotable_path_name = (
    (
        Combine(
            dquote.suppress()
            + pathname_base_dquote
            + dquote.suppress()
        )
        ^ Combine(
            squote.suppress()
            + pathname_base_squote
            + squote.suppress()
        )
        ^ pathname_base
    )('path_name')
)
dequotable_path_name.setName('<path_name>')

dequoted_path_name = (
    (
        Combine(
            dquote.suppress()
            + pathname_base_dquote
            + dquote.suppress()
        )
        ^ Combine(
            squote.suppress()
            + pathname_base_squote
            + squote.suppress()
        )
    )('quoted_path_name')
)
dequoted_path_name.setName('<quoted_path_name>')

# Bind9 naming convention

charset_name_base = alphanums + '_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon nor curly braces allowed
#  Word(alphanums + '_-.')
charset_name_dquotable = charset_name_base + "'"
charset_name_squotable = charset_name_base + '"'
name_base = Word(charset_name_base, max=64)
name_dquotable = Combine(Char('"') + Word(charset_name_dquotable, max=62) + Char('"'))
name_squotable = Combine(Char("'") + Word(charset_name_squotable, max=62) + Char("'"))
quotable_name = (
        name_squotable
        ^ name_dquotable
        ^ name_base
)('name')
quotable_name.setName('<quotable_name>')
quoted_name = (
    name_squotable
    ^ name_dquotable
)('name')
quoted_name.setName('<quoted_name>')
name_type = copy.deepcopy(quotable_name)

# dequotable_name
name_dedquotable = Combine(
    Char('"').suppress()
    - Word(charset_name_dquotable, max=62)
    - Char('"').suppress())
name_desquotable = Combine(
    Char("'").suppress()
    - Word(charset_name_squotable, max=62)
    - Char("'").suppress())
dequotable_name = (
        name_desquotable
        ^ name_dedquotable
        ^ name_base
)('name')
dequotable_name.setName('<quotable_name>')

dequoted_name = (
    name_desquotable
    ^ name_dedquotable
)('name')
dequoted_name.setName('<quoted_name>')

# Quoteable acl name
# acl_name can begin with a digit/alpha/certain-symbol
# acl_name cannot use '/!#' charset, as well as '{};\'\"'
charset_acl_name_base = alphanums\
                        + '_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon nor curly braces allowed
charset_acl_name_dquotable = charset_acl_name_base + "'"
charset_acl_name_squotable = charset_acl_name_base + '"'
acl_name_base = Word(charset_acl_name_base, max=64)
acl_name_dquotable = Combine(Char('"') + Word(charset_acl_name_dquotable, max=62) + Char('"'))
acl_name_squotable = Combine(Char("'") + Word(charset_acl_name_squotable, max=62) + Char("'"))

acl_name = (
        acl_name_squotable
        ^ acl_name_dquotable
        ^ acl_name_base
)('acl_name')
acl_name.setName('<acl-name>')

charset_keysecret_base = alphanums + '+/='
charset_keysecret_dquotable = charset_keysecret_base + "'"
charset_keysecret_squotable = charset_keysecret_base + '"'

keysecret_base = Word(charset_keysecret_base, max=32767)
keysecret_dquotable = Combine(Char('"') + Word(charset_keysecret_dquotable, max=32765) + Char('"'))
keysecret_squotable = Combine(Char("'") + Word(charset_keysecret_squotable, max=32765) + Char("'"))

# key_secret is being obsoleted, use quoteable_key_secret instead
key_secret = (
        keysecret_squotable
        ^ keysecret_dquotable
        ^ keysecret_base
)('key_secret')
key_secret.setName('<secret_string>')
quotable_key_secret = copy.deepcopy(key_secret)
quotable_key_secret.setName('<quotable_key_secret')
quoted_key_secret = (
    keysecret_squotable
    ^ keysecret_dquotable
)('key_secret')
quoted_key_secret.setName('<quoted_key_secret')

keysecret_dedquoted = Combine(
    Char('"').suppress()
    - Word(charset_keysecret_dquotable, max=32765)
    - Char('"').suppress())
keysecret_desquoted = Combine(
    Char("'").suppress()
    - Word(charset_keysecret_squotable, max=32765)
    - Char("'").suppress())
key_secret_dequoted = (
        keysecret_desquoted
        ^ keysecret_dedquoted
)('key_secret').setName('<quoted-key-secret>')
key_secret_dequotable = (
        keysecret_desquoted
        ^ keysecret_dedquoted
        ^ keysecret_base
)('key_secret').setName('<quotable-key-secret>')

g_expose_secrets = False

charset_key_id_base = alphanums + '_-'
charset_key_id_dquotable = charset_key_id_base + "'"
charset_key_id_squotable = charset_key_id_base + '"'
key_id_base = Word(charset_key_id_base, max=62)
key_id_dquotable = Combine(Char('"').suppress() + Word(charset_key_id_dquotable, max=64) + Char('"').suppress())
key_id_squotable = Combine(Char("'").suppress() + Word(charset_key_id_squotable, max=64) + Char("'").suppress())

key_id = (
        key_id_dquotable
        ^ key_id_squotable
        ^ key_id_base
)('key_id')
key_id.setName('<key_id>')
# key <key-name>
key_id_keyword_and_name_pair = (
        Literal('key').suppress()
        + (
            key_id('')
        )('key_id')
)
key_id_keyword_and_name_pair.setName('"key" <key_id>')

# key <key-name>;
key_id_keyword_and_name_element = (
        key_id_keyword_and_name_pair
        + semicolon
)  # propagate 'key_id' ResultsName up from 'key_id' parser element.
key_id_keyword_and_name_element.setName('"key" <key_id>;')

# TSIG session key name
tsig_session_key_name = (
        key_id_dquotable
        ^ key_id_squotable
        ^ key_id_base
)('tsig_session_keyname')
tsig_session_key_name.setName('<TSIG-session-keyname>')


# <base-64-char> 	:: <alpha> | <decimal-digit> | "+" | "/" | "=" ;
charset_base64 = alphanums + '+/'  # we do not allow '=' terminator(s)
base64_base = Word(charset_base64, min=1, max=8096)
base64_base.setName('<base64>')

base64_base_squotable = Word(charset_base64 + "'")
base64_base_dquotable = Word(charset_base64 + '"')

quoted_base64 = Combine(
                    (
                            Char('"').suppress()
                            - base64_base
                            - Char('"').suppress()
                    )
                    ^ (
                            Char("'").suppress()
                            - base64_base
                            - Char("'").suppress()
                    )
)(None)
quoted_base64.setName('<quoted_base64>')
quotable_base64 = (
    base64_base_squotable
    ^ base64_base_dquotable
    ^ base64_base
)
quotable_base64.setName('<quotable_base64>')

# Quoteable view name
# view_name can begin with a digit/alpha/certain-symbol
# view_name cannot use '/!#' charset, as well as '{};\'\"'
charset_view_name_base = alphanums\
                         + '_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon nor curly braces allowed
charset_view_name_dquotable = charset_view_name_base + "\'"
charset_view_name_squotable = charset_view_name_base + '\"'

view_name_base = Word(charset_acl_name_base, max=64)
view_name_base.setName('<view-name-unquoted>')

view_name_dquotable = Combine(Char('"') + Word(charset_view_name_dquotable, max=62) + Char('"'))
view_name_squotable = Combine(Char("'") + Word(charset_view_name_squotable, max=62) + Char("'"))

view_name = (
        view_name_dquotable(None)
        | view_name_squotable(None)
        | view_name_base(None)
)('view_name')
view_name.setName('<view-name>')

# zone_name can begin with a digit/alpha/certain-symbol
# zone_name cannot use '/!#' charset, as well as '{};\'\"'
charset_zone_name_base = alphanums\
                         + '_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon nor curly braces allowed
charset_zone_name_dquotable = charset_zone_name_base + "'"
charset_zone_name_squotable = charset_zone_name_base + '"'

zone_name_base = Word(charset_zone_name_base)('zone_name')
zone_name_base.setName('<zone-name-unquoted>')

zone_name_dquotable = Combine(dquote + Word(charset_zone_name_dquotable) + dquote)('zone_name')
zone_name_squotable = Combine(squote + Word(charset_zone_name_squotable) + squote)('zone_name')

zone_name = (
    zone_name_dquotable
    | zone_name_squotable
    | zone_name_base
)('zone_name')
zone_name.setName('<zone_name>')

zone_name_dedquotable = Combine(
    dquote.suppress()
    - Word(charset_zone_name_dquotable)
    - dquote.suppress())('zone_name')
zone_name_desquotable = Combine(
    squote.suppress()
    - Word(charset_zone_name_squotable)
    - squote.suppress())('zone_name')
dequotable_zone_name = (
    zone_name_dedquotable
    | zone_name_desquotable
    | zone_name_base
)('zone_name')
dequotable_zone_name.setName('<zone_name>')


# Quoteable fqdn name
charset_fqdn_name_base = alphanums + '_-.'
charset_fqdn_name_has_squote = charset_fqdn_name_base + "'"
charset_fqdn_name_has_dquote = charset_fqdn_name_base + '"'
fqdn_name_base = Word(charset_fqdn_name_base)
fqdn_name_base.setName('<fqdn-name-unquoted>')

fqdn_name_squotable = Combine(
    squote
    + Word(charset_fqdn_name_has_dquote)
    + squote
)

fqdn_name_dquotable = Combine(
    dquote
    + Word(charset_fqdn_name_has_squote)
    + dquote
)

fqdn_name = (
        fqdn_name_squotable
        | fqdn_name_dquotable
        | fqdn_name_base
)('fqdn_name')
fqdn_name.setName('<fqdn-name>')

fqdn_name_squoted = Combine(
    squote.suppress()
    + Word(charset_fqdn_name_has_dquote)
    + squote.suppress()
)

fqdn_name_dquoted = Combine(
    dquote.suppress()
    + Word(charset_fqdn_name_has_squote)
    + dquote.suppress()
)

fqdn_name_dequoted = (
        fqdn_name_squoted
        | fqdn_name_dquoted
)('fqdn_name')
fqdn_name_dequoted.setName('<fqdn-name(dequoted)>')

fqdn_name_dequotable = (
        fqdn_name_squoted
        | fqdn_name_dquoted
        | fqdn_name_base
)('fqdn_name')
fqdn_name_dequotable.setName('<fqdn-name(dequotable)>')

# Username can only contain alphanumeric characters and '_', '+', '-', or '.'.
# Username should have between 3 and 32 characters.
charset_krb5_username = alphanums + '-+_.'
charset_krb5_realm = fqdn_name

krb5_realm_name = fqdn_name_dequotable('<realm>')('realm')
krb5_primary_name = Word(charset_krb5_username, min=1, max=32)('primary')
krb5_instance_name = Word(
    charset_krb5_username, min=1, max=256
)('instance')  # limited to length of FQDN

# Valid inputs:
#   user@DOMAIN.COM
#   user/admin@DOMAIN.COM
#   host/host.domain.com@DOMAIN.COM
#   root/host.domain.com@DOMAIN.COM
#   nfs/host.domain.com@DOMAIN.COM
#   user@DOMAIN.COM:123
#   user/admin@DOMAIN.COM:123
#   host/host.domain.com@DOMAIN.COM:234
#   root/host.domain.com@DOMAIN.COM:456
#   nfs/host.domain.com@DOMAIN.COM:890

#  krb5_principal_name max=(254+1+16))  # limited to length of FQDN + '/' + URI
krb5_principal_name_base = (
        Combine(
            krb5_primary_name
            - '/'
            - krb5_instance_name
            - '@'
            - krb5_realm_name
        )
        ^ Combine(
            krb5_primary_name
            - '/'
            - krb5_realm_name
        )
        ^ Combine(
            krb5_primary_name
            - '@'
            - krb5_realm_name
        )
)('principal')
krb5_principal_name_base.setName('<krb5_principal_name_base>')

krb5_principal_name_squoted = (squote - krb5_principal_name_base - squote)
krb5_principal_name_dquoted = (dquote - krb5_principal_name_base - dquote)

krb5_principal_name = (
        krb5_principal_name_squoted
        | krb5_principal_name_dquoted
        | krb5_principal_name_base
)
krb5_principal_name.setName('<principal>')

check_options = (
        CaselessLiteral('warn')
        | CaselessLiteral('fail')
        | CaselessLiteral('ignore')
)('check_type')
check_options.setName('( warn | fail | ignore )')

seconds_type = Word(nums).setParseAction(
    lambda toks: int(toks[0]), max=11
)('seconds')
seconds_type.setName('<seconds>')

# heartbeat-interval
minute_type = Word(nums).setParseAction(
    lambda toks: int(toks[0]), max=11
)('minutes')
minute_type.setName('<minutes>')

# sig-validity-interval
days_type = Word(nums).setParseAction(
    lambda toks: int(toks[0]), max=11
)('days')
days_type.setName('<days>')

# lame-type, interface-interval
number_type = Word(nums).setParseAction(
    lambda toks: int(toks[0]), max=15
)('number')
number_type.setName('<number>')

fixedpoint_type = (
    Word(nums)
    - Optional(
        Literal('.')
        - Optional(Word(nums, min=1, max=1))
    )
).setParseAction(
    lambda toks: float(toks[0]), max=15
)('fixedpoint').setName('<fixedpoint>')

percentage_type = (
    Word(nums).setParseAction(
        lambda toks: int(toks[0]), max=15
    )
    + Literal('%').suppress()
).setName('<percentage>')

# max-cache-size
byte_type = Word(nums, max=3)('byte').setParseAction(
    lambda toks: int(toks[0]),
)
byte_type.setName('<byte>')

# Breakout the letter notation (removed Combine())
size_spec_plain = (
    Group(
        Word(nums).setParseAction(lambda toks: int(toks[0]), max=10)('amount')
        + Optional(
            (
                Literal('K')
                | Literal('k')
                | Literal('M')
                | Literal('m')
                | Literal('G')
            )('unit')
        )
    )('size_spec')
).setName('<size-spec>')

size_spec_nodefault = (
    (
        Group(
            Word(nums).setParseAction(lambda toks: int(toks[0]), max=10)
            - Optional(
                CaselessLiteral('K')
                | CaselessLiteral('M')
                | CaselessLiteral('G')
            )
        )
        | CaselessLiteral('unlimited')
    )
).setName('( <size-spec> | unlimited )')

size_spec = (
    Group(
            ungroup(size_spec_nodefault)
            | CaselessLiteral('default')
    )
)('size')
size_spec.setName('( <size-spec> | unlimited | default )')

dlz_name_type = Word(alphanums + '_-.', max=63)('dlz_name')
database_name_type = Word(alphanums + '_-.', max=63)('dlz_name')

charset_master_name_base = alphanums + '_-'
master_name_base = Word(charset_master_name_base, max=62)
master_name = copy.deepcopy(master_name_base('master_name'))

master_name_base_dequoted = (
    (
        Char('"').suppress()
        - Word(charset_master_name_base, max=62)
        - Char('"').suppress()
    )
    ^ (
        Char("'").suppress()
        - Word(charset_master_name_base, max=62)
        - Char("'").suppress()
    )
)

master_name_dequotable = (
       ungroup(master_name_base_dequoted)
       ^ master_name
)('master_name').setName('<master-name>')

master_name.setName('<master_name>')

# iso8601 is not a naive nor aware ISO time-interval
# iso8601 is a delta time (or duration)
iso8601_duration = Word(
    alphanums + '-.+:', min=1, max=63
)('iso8601_duration').setName('<iso8601_duration_new>')

config_base_charset = alphanums + ' \t_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon allowed
config_base = Word(config_base_charset, min=1, max=4086)

# #############################################################
# Series
# #############################################################

# '<key_id>;'
key_id_list = key_id + semicolon

# '<key_id>; <key_id>; ...'
key_id_list_series = (
    Group(
        OneOrMore(
            ungroup(key_id_list)
        )
    )('key_ids')
)
key_id_list_series.setName('<key_list>;')


#  Algorithms used by PKI
charset_algorithm = alphanums + '-'
algorithm_name = Word(charset_algorithm, min=1, max=32)('algorithm_name')
algorithm_name.setName('<algorithm_name>')

algorithm_name_list_set = (
        Word(charset_algorithm, min=1, max=32)('algorithm_name')
        - semicolon
)
algorithm_name_list_set.setName('<algorithm_name>;')

algorithm_name_list_series = (
    Group(
        OneOrMore(
            ungroup(algorithm_name)
            - semicolon
        )
    )('algorithm_name')
)
algorithm_name_list_series.setName('<algorithm_name>; [ <algorithm_name>; ... ]')

#  Algorithms used by TLS
charset_tls_algorithm = alphanums + '.-'
tls_algorithm_name = Word(charset_tls_algorithm, min=1, max=32)('tls_algorithm_name')
tls_algorithm_name.setName('<tls_algorithm_name>')

tls_algorithm_name_list_set = (
        Word(charset_algorithm, min=1, max=32)('tls_algorithm_name')
        - semicolon
)
tls_algorithm_name_list_set.setName('<tls_algorithm_name>;')

tls_algorithm_name_list_series = (
    Group(
        OneOrMore(
            ungroup(tls_algorithm_name)
            - semicolon
        )
    )('tls_algorithm_name')
)
tls_algorithm_name_list_series.setName('<tls_algorithm_name>; [ <tls_algorithm_name>; ... ]')

# Primary (formerly masters) name

# Quoteable primary name
# Yes, ISC Bind9 supports period in primary_name_type
charset_primary_name = alphanums \
                       + '_-.+~@$%^&*()=[]\\|:<>`?'  # no semicolon nor curly braces allowed
primary_name_type = Word(charset_primary_name, min=1, max=63)('primary_name_type')
primary_name_type.setName('<primary_name>')
primary_name_type_squotable = Word(charset_primary_name + '"')
primary_name_type_dquotable = Word(charset_primary_name + "'")

primary_name_type_with_squote = Combine(
    dquote
    - primary_name_type_dquotable
    + dquote
)

primary_name_type_with_dquote = Combine(
    squote
    - primary_name_type_squotable
    + squote
)

# the term primary_name used with the :
#   * primaries clause,
#   * primaries statement or
#   * also-notify statement of options/view/zone clauses.
primary_id = (
        primary_name_type_squotable
        | primary_name_type_dquotable
        | primary_name_type
)('primary_id')


# Boolean support

test_data_boolean_passing = [
    'yes',
    'YES',
    'no',
    'No',
    '0',
    '1',
    'True',
    'False',
    'FALSE',
    'TRUE',
    'true',
    'false',
    'tRue',
    'faLse',
]
test_data_boolean_failing = [
    'yeah',
    'nope',
    'on',
    'off',
    '2',
    'Truly',
]


def unit_test_booleans(self, parser_elements):
    """

    :param self:
    :type self:
    :param parser_elements:
    :type parser_elements:
    :return:
    :rtype:
    """
    cumulative_result_false = False
    cumulative_result_true = True
    for this_stmt_name, this_parser_element in parser_elements:
        this_parser_element.setWhitespaceChars(' ')

        # Try every valid boolean values here
        expected_result = True
        for this_test_data in test_data_boolean_passing:

            constructed_stmt = this_stmt_name + ' ' + this_test_data + ';'
            print('stmt: ', constructed_stmt)
            result = this_parser_element.runTests(
                [constructed_stmt],
                failureTests=(not expected_result))
            # Only takes one detractor to fail the whole unit test run
            print('result: ', result[0])
            if not result:
                cumulative_result_true = not expected_result
        self.assertEqual(cumulative_result_true, expected_result)

        # Try every invalid boolean values here
        expected_result = False
        for this_test_data in test_data_boolean_failing:

            constructed_stmt = this_stmt_name + ' ' + this_test_data + ';'
            print('stmt: ', constructed_stmt)
            result = this_parser_element.runTests(
                [constructed_stmt],
                failureTests=(not expected_result))

            # Only takes one detractor to fail the whole unit test run
            print('result: ', result[0])
            if not result:
                cumulative_result_false = not expected_result
        self.assertEqual(cumulative_result_false, expected_result)
    return (cumulative_result_false is False) & (cumulative_result_true is True)


def trace_me(a_tokens):
    """
    Tracer routine
    :param a_tokens: takes in a list of token
    :type a_tokens: outputs a list of token
    """
    print('trace_me trace_me trace_me trace_me trace_me')
    a_tokens.dump()
    # print('a_tokens.dump(): %s\n' % a_tokens.dump())
    # raise TypeError(oops)


# DO NOT USE run_me for multiline match
def run_me(a_parse_element, a_test_data, a_parse_all=True, a_comment='#',
           a_full_dump=True, a_print_results=True, a_failure_tests=False, a_post_parse=None,
           a_file=None, a_debug=True):
    """
    run_me takes in a multiple lines of test data,
           one line for each test and
           returns a list of test results.
    NOTE: Not to be used for multiline test data as a single
          test (instead, use parse_me).
          There's no way to check for accidental misuse of multiline
          so consider yourself warned here.
    :param a_parse_element:
    :param a_test_data:
    :param a_parse_all:
    :param a_comment:
    :param a_full_dump:
    :param a_print_results:
    :param a_failure_tests:
    :param a_post_parse:
    :param a_file:
    :param a_debug:
    :return:
    """
    pp = PrettyPrinter(indent=2, width=45, compact=True)
    result = a_parse_element.runTests(tests=a_test_data, parseAll=a_parse_all,
                                      comment=a_comment, fullDump=a_full_dump,
                                      printResults=a_print_results, failureTests=a_failure_tests,
                                      postParse=a_post_parse, file=a_file)
    if not a_failure_tests:
        print('Test result of "%s" Valid Syntax (all should pass)' % a_parse_element)
    else:
        print('Test result of "%s" Invalid Syntax (all should fail)' % a_parse_element)
    print('Test content: "%s"' % a_test_data)
    if result is None:
        print('parse_me: result: None')
    else:
        print('result: ', result)
        pp.pprint(result)
        if not result[0]:
            assert False
    return result


pos = -1


def assert_parser_result_dict(parser_element,
                              test_strings,
                              expected_results,
                              assert_flag=True,
                              message=''):
    """
    A nice unit test tool which provides an assert()-like function
    that takes an string, parse the string, takes its computed
    Pythonized list/dict and compares the result against its
    expected Pythonized result.

    :param parser_element:  ParserElement class to exercise
    :param test_strings:  A string in which to be parsed by parser_element.
                          Or it can be a list of strings ['a', 'b'].
    :param expected_results:  A Python list in which to expect
                              If a_test_data is a list, then this argument
                              shall also be a list of expected result
    :param assert_flag:  If True, then expected result must match or an
                         exception gets raised.
                         If False, then parse MUST fail or expected
                         result does not match, else an exception
                         gets raised
    :param message:  If supplied, outputs the message associated with
                     this error message
    :return: Always returns True (exception handles the False, like
             an assert() class would do)
    """
    retsts = None

    def incr_pos(fn):
        def _inner(*args):
            global pos
            pos += 1
            print("\t" * pos, end="")
            return fn(*args)

        return _inner

    def decr_pos(fn):
        def _inner(*args):
            global pos
            print("\t" * pos, end="")
            pos -= 1
            return fn(*args)

        return _inner

    import pyparsing
#    pyparsing._defaultStartDebugAction = incr_pos(pyparsing._defaultStartDebugAction)
#    pyparsing._defaultSuccessDebugAction = decr_pos(pyparsing._defaultSuccessDebugAction)
    #pyparsing._defaultExceptionDebugAction = incr_pos(pyparsing._defaultExceptionDebugAction)
    try:
        parser_element = parser_element.setDebug(True)
        result = parser_element.parseString(test_strings, parseAll=True)
        from pprint import PrettyPrinter
        pp = PrettyPrinter(indent=2, width=66, compact=False)
        if result.asDict() == {}:
            print('Dict() empty; BAD result:', end='')
            pp.pprint(result)
            retsts = False
        else:
            print('Good result:')
            pp.pprint(result.asDict())
            # Convert ParserElement into Python List[]
            retsts = (result.asDict() == expected_results)
        print('expecting: ')
        pp.pprint(expected_results)
    except ParseException as pe:
        print('ParseException:')
        print(pe.line)  # affected data content
        print(' ' * (pe.column - 1) + '^')  # Show where the error occurred
        print(pe)
        ParseException.explain(pe)
        retsts = False
    except ParseSyntaxException as pe:
        print('ParseSyntaxException:')
        print(test_strings)  # affected data content
        print(' ' * (pe.column - 1) + '^')  # Show where the error occurred
        print(pe)
        # print(parser_element.errmsg)
        retsts = False
        # raise InvalidConfiguration(error_msg)
    except Exception as pe:
        exc_type, value, traceback = sys.exc_info()
        assert exc_type.__name__ == 'NameError'
        print("Failed with exception [%s]" % exc_type.__name__)
        print(pe)
    except:
        print('UNKNOWN exception error')
        print("test_strings: ", test_strings)
    if retsts == assert_flag:
        print('assert(True)')
        return True
    else:
        errmsg = 'Error(assert=' + str(False) + '): ' + message + '\"' + str(test_strings) + '\".'
        raise SyntaxError(errmsg)


def assert_parser_result_dict_true(parser_element, test_strings, expected_results, message=''):
    """
    A nice wrapper routine to ensure that the word 'True' is in the
    function name.
    """
    assert_parser_result_dict(parser_element=parser_element,
                              test_strings=test_strings,
                              expected_results=expected_results,
                              assert_flag=True, message=message)


def assert_parser_result_dict_false(parser_element, test_strings, expected_results, message=''):
    """
    A nice wrapper routine to ensure that the word 'False' is in the
    function name.
    """
    assert_parser_result_dict(parser_element=parser_element,
                              test_strings=test_strings,
                              expected_results=expected_results,
                              assert_flag=False, message=message)


def parse_me(apm_parse_element,
             apm_test_data,
             apm_assert_flag=True,
             apm_debug=False,
             apm_verbosity=False):
    """
     Parse this particular element

    :param apm_parse_element:
    :type apm_parse_element:
    :param apm_test_data:
    :type apm_test_data:
    :param apm_assert_flag:
    :type apm_assert_flag:
    :param apm_debug:
    :type apm_debug:
    :param apm_verbosity:
    :type apm_verbosity:
    :return:
    :rtype:
    """
    apm_parse_element.setDebug(flag=apm_debug)
    if apm_verbosity:
        print('\ntest_strings: %s' % apm_assert_flag)
        print('Parse Element: ', end='')
        print(apm_parse_element)
        print('Test Data: "%s":' % apm_test_data)
    try:
        # parseAll=True - raise ParseException if the grammar does not process
        # the complete input string
        greeting = apm_parse_element.parseString(apm_test_data, parseAll=True)
        x = greeting.asList()
        pp = PrettyPrinter(indent=2, width=66, compact=False)
        print("Result: ", pp.pprint(x))
        if len(greeting) == 0:
            retsts = None
        else:
            retsts = greeting
    except ParseException as pe:
        print('ParseException:')
        print(pe.line)  # affected data content
        print(' ' * (pe.column - 1) + '^')  # Show where the error occurred
        print(pe)
        ParseException.explain(pe)
        retsts = None
    except ParseSyntaxException as pe:
        print('ParseSyntaxException:')
        print(apm_test_data)  # affected data content
        print(' ' * (pe.column - 1) + '^')  # Show where the error occurred
        print(pe)
        # print(parser_element.errmsg)
        retsts = None
        # raise InvalidConfiguration(error_msg)

    status = not not retsts
    if status == apm_assert_flag:
        print('assert(True)')
        return retsts
    errmsg = 'Error(assert=' + str(apm_assert_flag) + '): \"' + apm_test_data + '\".'
    raise SyntaxError(errmsg)


def test_main(tm_parse_element):
    """
    test main routine

    :param tm_parse_element:
    :type PyParsing.ParseElement:
    :return:
    :rtype:
    :return:

    python_script              # defaults to STDIN for input a_file
                                 (good for quick test or cut-n-paste)
    python_script -t           # Exercise built-in unit test
    python_script <filespec>   # Read a_file and syntax-check it
    python_script -v           # Increase verbosity level
    python_script -d           # Increase PyParsing debugging
    """
    pgm_basename = os.path.basename(sys.argv[0])

    prgm_desc = 'Exercise or test the {} function in {} python script against ParserElement "{}" '\
        .format(
            tm_parse_element.__class__.__name__,
            pgm_basename,
            tm_parse_element)
    parser = argparse.ArgumentParser(description=prgm_desc)
    parser.add_argument('-v', '--verbose', action='store_true', help='Run with extra messages')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Run with PyParsing debugging enabled; '
                             + 'outputs "Match/Matched" a_debug lines')

    if UNIX_PIPE_SUPPORT:
        default_arg1 = '-'
    else:
        default_arg1 = None
    # nagrs='?' is zero or one argument exactly
    parser.add_argument('filespec',
                        type=argparse.FileType('r'),
                        default=default_arg1,
                        nargs='?',
                        help='Input a_file to read and parse')
    args = parser.parse_args()
    if args.verbose:
        print('"Number of arguments: ', len(sys.argv))
        print('The arguments are: ', str(sys.argv))
        print('argparse.args:', args)
    retsts = 0
    test_data = None
    if not UNIX_PIPE_SUPPORT:
        # test if file exist
        if args.filespec is None:
            retsts = errno.ENOTTY  # Most people don't want UNIX pipe support
        elif not os.access(args.filespec.name, os.R_OK):
            print("Cannot read {} file. Exiting...".format(args.filespec.name))

    # If no a_file given, we default to STDIN as a a_file to be opened
    # Naturally, you'll have to press Ctrl-D to close the a_file.
    if args.verbose:
        print('parser_element:', tm_parse_element)
    try:
        test_data = args.filespec.read()
        args.filespec.close()
    except Exception as pe:
        print('Exception:')
        print(pe)
        retsts = errno.EBADFD

    if test_data:
        if args.debug:
            tm_parse_element.setDebug()
        try:
            tm_parse_element.ignore(cppStyleComment)
            tm_parse_element.ignore(pythonStyleComment)
            result = tm_parse_element.parseString(test_data, parseAll=True)
            result_text = result.asList()
            print("Result: ", result_text)
            if len(result) == 0:
                retsts = errno.EBADE
            else:
                retsts = 0
        except ParseException as pe:
            print('ParseException:')
            print(pe.line)  # affected data content
            print(' ' * (pe.column - 1) + '^')  # Show where the error occurred
            print(pe)
            ParseException.explain(pe)
            retsts = errno.ELIBSCN
        except ParseSyntaxException as pe:
            print('ParseSyntaxException:')
            print(test_data)  # affected data content
            print(' ' * (pe.column - 1) + '^')  # Show where the error occurred
            print(pe)
            retsts = errno.ELIBBAD
    else:
        retsts = errno.ENODATA
        if args.verbose:
            print("test_data is empty")

    # Build return values
    return_list = {}
    return_list['verbosity'] = args.verbose
    return_list['a_debug'] = args.debug
    return_list['filespec'] = args.filespec
    return_list['errcode'] = retsts
    return return_list


def x_dump_var(s, fn=repr):
    """

    :rtype: None
    :param s: name of the string
    :type s: str
    :param fn:
    :type fn:
    """
    print("%s -> %s" % (s, fn(eval(s))))

    x_dump_var("list(result)")
    x_dump_var("result.dump()", str)
    x_dump_var("result[0]")
    x_dump_var("result.domain_name")
    x_dump_var("'domain_name' in result")
    x_dump_var("result['domain_name']")


if __name__ == '__main__':
    result_list = test_main(isc_boolean)
    retcode = result_list['errcode']

    # Is it a unit test or not
    if not result_list['filespec']:
        retcode = errno.EINVAL
    # Unix pipe must be silent
    elif result_list['filespec'].name != '<stdin>':
        # Ordinary a_file operation
        print('Result:', result_list['errcode'])

    if result_list['verbosity']:
        print('Result:', result_list)
    sys.exit(retcode)
