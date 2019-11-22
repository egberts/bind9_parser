#!/usr/bin/env python3
"""
File: isc_domain.py

Element: domain

Title: Elements providing domain name syntaxes


Description: Provides domain-related grammar in PyParsing engine
             for ISC-configuration style

 For domain names to be valid, domain names MUST:

 * have a minimum of 3 and a maximum of 63 characters;
 * begin with a letter or a number and end with a letter or a number;
 * use the English character set and may contain letters (i.e., a-z, A-Z),
       numbers (i.e. 0-9) and dashes (-) or a combination of these;
 * neither begin with nor end with a dash (-);
 * not contain a dash in the third and fourth positions (e.g. www.ab- -cd.com);
 * not include a space (e.g. www.ab cd.com);
 * not include underscore (e.g www.ab_cd.com)

 * Also RFC4343 states that label (between periods) cannot be greater
   than 63 chars Nor total length of a fully-qualified domain name
   cannot exceed 253 chars.
 * Also, for input data purposes, a domain_label cannot have its case changed
   from its original upper or loewr case. Otherwise, you'd be breaking
   international IDN
 * Only the first label may only just contain "*", but never used asterisk
   in any other positions or labels of the domain or subdomain name.

Note: We cannot enforce TLD syntax because many option settings allows for
      just the domain label (congress) or its fully-qualified domain
      name (www.congress.gov). So, additional out-of-band syntax checking
      would be required for domain-label-syntax fields

      Same thing to its 2nd-level domain name, as TLD described above.

      Hostname, while restrictive in by some OS-imposed ban on dash/hyphen
      and underscore symbols, we too cannot enforce domain label syntax
      either because it may be a liberal 3rd-level subdomain naming
      convention such as '_53._tcp.example.com' or
      LetsEncrypt's '_acme-challenge.example.com'

      HOWEVER, if such a FQDN ends with a period ('.'), then we could
      enforce this with real-world FQDN naming convention for 2nd and TLD
      name syntax checking, but ... not here, not now.

      A deviation (or more accurately, expanding) from ISC DNS
      "domain_name" convention, we use:

        - TLD for top-level domain
        - DOMAIN for 2nd-level domain
        - SUBDOMAIN for 3rd-level (and lower) domain

      And DOMAIN-GENERIC for all 3 levels of domain names.
"""
from pyparsing import Optional, Word, Combine, \
    srange, alphanums, ZeroOrMore, \
    Literal, alphas, Char, Regex, OneOrMore
from bind9_parser.isc_utils import squote, dquote

g_test_over_63_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc"

#
# IETF RFC1035 covers DNS naming conventions
#
# <domain> ::= <subdomain> | " "
# <subdomain> ::= <label> | <subdomain> "." <label>
# <let-dig> ::= <letter> | <digit>
# <let-dig-hyp> ::= <let-dig> | "-"
# <let-dig-underscore> ::= <let-dig> | "_"
# <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
# <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]   # RFC 1035

# We tossed out RFC1035, et. al.
# We support the following ISC Bind9/DHCP-supported domain name syntax
#     example.com
#     example.com.
#     *.example.com
#     _imap._tcp.example.com  # RFC 6186
#     xn--abcdef.example.com  # "ACE prefix" is 'xn--'
#     Mnchen-3ya.example.com  # PunyCode (München)
# Error-checking are done later

#  RFC 2181, section 11, Name syntax
domain_charset_alphas = alphas
domain_charset_alphanums = alphanums
domain_charset_alphanums_underscore = alphanums + '_'
domain_charset_alphanums_dash = alphanums + '-'
domain_charset_alphanums_dash_underscore = alphanums + '_-'
domain_charset_wildcard = '*'

domain_alpha = Word(domain_charset_alphas)
domain_alpha.setName('<alpha>')

domain_alphanum = Word(domain_charset_alphanums)
domain_alphanum.setName('<alphanum>')

domain_alphanum_dash = Word(domain_charset_alphanums_dash)
domain_alphanum_dash.setName('<alphanum-hyphen>')

domain_alphanum_underscore = Word(domain_charset_alphanums_underscore)
domain_alphanum_underscore.setName('<alphanum-underscore>')

domain_alphanum_dash_underscore = Word(domain_charset_alphanums_dash_underscore)
domain_alphanum_dash_underscore.setName('<alphanum-hyphen-underscore>')

# Maximum length of TLD is 63.
# Currently, 25 is the most seen (source: http://data.iana.org/TLD/tlds-alpha-by-domain.txt)
tld_label = Word(domain_charset_alphas,  min=2, max=24)
tld_label_regex = '[A-Za-z]{3,24}'
tld_label.setName('<tdl-label>')

domain_label_regex = r'[a-zA-Z0-9]{1,1}([a-zA-Z0-9\-]{0,61}){0,1}[a-zA-Z0-9]{1,1}'
domain_label = Regex(domain_label_regex)
# RFC1123 permitted labels starting with a digit
    # Word(domain_charset_alphanums, exact=1)
    # + Word(domain_charset_alphanums_dash, min=1, max=61)
    # + Word(domain_charset_alphanums, exact=1)
domain_label.setName('<level2-domain-label>')

# NOGO: Do not consider merging subdomain_* with domain_generic_*
# For subdomains, we can use underscore, practically anywhere within its domain label
# Domain Registars mostly do not allow name registration having any underscore
# End-user may however deploy underscore anywhere outside of 2nd and top level domain name
subdomain_label_regex = '[A-Za-z0-9_]{1,1}(([A-Za-z0-9_\-]{0,61}){0,1}[A-Za-z0-9_]{1,1}){0,1}'
# We do not do IDN/PunyCode syntax enforcement here, that is outside the scope of this parser
subdomain_label = Regex(subdomain_label_regex)
subdomain_label.setName('<subdomain_label>')

# Generic Domain label, used for ANY level of its domain name
domain_generic_label = Word(domain_charset_alphanums_dash_underscore, min=1, max=63)
domain_generic_label.setName('<domain_generic_label>')
domain_generic_label.setResultsName('domain_name')

# domain_fqdn is very, very strict.  Use sparingly; probably want to use domain_generic_fqdn
# Original pyparsing draft for domain_fqdn was this:
# domain_fqdn = Combine(
#     Optional(
#         ZeroOrMore(
#             subdomain_label
#             + Literal('.')
#         )
#         + domain_label
#         + Literal('.')
#     )
#     + tld_label
# )
#  Problem with above domain_fqdn is that PyParsing cannot do lookahead in time, so
#  we use the much-vaunted Regex() for domain_fqdn
domain_fqdn_regex = '('\
                        + '(' \
                            + subdomain_label_regex \
                            + '\.' \
                        + '){0,16}' + \
                        domain_label_regex + '\.' \
                    + '){0,1}'\
                    + tld_label_regex
domain_fqdn = Regex(domain_fqdn_regex)
domain_fqdn.setName('<strict-fqdn>')
domain_fqdn.setResultsName('domain_name')

# Generic fully-qualified domain name (less stringent)
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

quoted_domain_generic_fqdn = (
        Combine(squote - domain_generic_fqdn - squote)
        | Combine(dquote - domain_generic_fqdn - dquote)
)
quoted_domain_generic_fqdn.setName('<quoted_domain_name>')

quotable_domain_generic_fqdn = (
        Combine(squote - domain_generic_fqdn - squote)
        | Combine(dquote - domain_generic_fqdn - dquote)
        | domain_generic_fqdn
)
quotable_domain_generic_fqdn.setName('<quotable_domain_name>')

#  Following is commonly used in association with DNS zone records
rr_fqdn_w_absolute = Combine(
    domain_generic_fqdn
    + Optional(Literal('.'))
)
rr_fqdn_w_absolute.setName('<rr-fqdn-with-abs>')
rr_fqdn_w_absolute.setResultsName('domain_name')

# rr_domain_name is uzed in association with DNS zone records
# by 'update-policy', a zone-specific option
rr_domain_name_type = Combine(
    domain_generic_fqdn
    + Optional(Literal('.'))
)
rr_domain_name_type.setName('<rr-name>')
rr_domain_name_type.setResultsName('domain_name')

# rr_domain_name may be '*.example.net', '*.congress.gov.', or '*'
rr_domain_name_or_wildcard_type = (
        rr_domain_name_type
        | Char(domain_charset_wildcard)
)
rr_domain_name_or_wildcard_type.setName('<rr-name-or-wildcard>')
rr_domain_name_or_wildcard_type.setResultsName('domain_name')

# Bind9 convention
# domain_name = rr_fqdn_w_absolute
# domain_name.setName('domain_name')

# hostname do not have underscore, just [a-z0-9\-]
# OS imposes a minimum size of 3 for hostname, but DNS server can support 1-char
# RFC952 caps hostname at 24 chars maximum.
# Hostname cannot be of dotted-quad notation
# Hostname cannot handle leadng/trailing hyphen/dash.
# Max length is 64 (since Linux 1.0+ via HOST_NAME_MAX)
host_name_first_char = Char(srange('[a-zA-Z0-9]'))
host_name_first_char.setName('<one_char_hostname>')

host_name_two_chars = Combine(Char(srange('[a-zA-Z0-9]')) + Char(srange('[a-zA-Z0-9]')))
host_name_two_chars.setName('<two_char_hostname>')

charset_host_name_middle_chars = srange('[a-zA-Z0-9]') + '-'
host_name_long_type = Regex('[a-zA-Z0-9]{1}[a-zA-Z0-9\-]{0,62}[a-zA-Z0-9]{1}')('hostname_long')
host_name_long_type.setName('<hostname_regex>')

# TODO block examples like 'example-.-nono'
host_name_just_the_hostname = (
    host_name_long_type
    | host_name_two_chars
    | host_name_first_char
)('hostname_indice')

host_name = (
    host_name_just_the_hostname
    | Combine(host_name_just_the_hostname + '.' + domain_fqdn)
)
host_name.setDebug()
# NOGO: Add antipattern of dotted quad notation toward 'hostname' (no need to, hostname does not allow period symbols
# host_name.setName('<hostname>')
# host_name.setResultsName('host_name')

