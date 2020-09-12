#!/usr/bin/env python3.7
"""
File: isc_inet.py

Element: inet

Title: Elements that covers Internet

Description: Provides inet-related grammar in PyParsing engine
             for ISC-configuration style

"""
from pyparsing import Word, nums, Combine, Group, \
    pyparsing_common, ZeroOrMore, Literal, Keyword,\
    ungroup, OneOrMore, Optional, Regex, Char, alphanums, hexnums
from bind9_parser.isc_utils import semicolon, squote, dquote


# def ip4_subnet_range_check(strg, loc, toks):
#     """
#     s = the original string being parsed
#     loc = the location of the matching substring
#     toks = a list of the matched tokens, packaged as a ParseResults object
#     """
#     value = int(toks[0])
#     if (value < 1) or (value > 31):
#         print("IPv4 subnet is out of range: %d" % value)
#         print("strg: %s" % strg)
#         print("loc: %s" % loc)
#     return None

charset_wildcard = '*'
charset_wildcard_squotable = '*"'
charset_wildcard_dquotable = "*'"
wildcard_base = Literal(charset_wildcard)
wildcard_squoted = Combine(squote + Literal(charset_wildcard) + squote)
wildcard_dquoted = Combine(dquote + Literal(charset_wildcard) + dquote)

wildcard_name = (
        wildcard_squoted
        | wildcard_dquoted
        | wildcard_base
)

dscp_port = Word(nums).setParseAction(lambda toks: int(toks[0]), max=3)
dscp_port.setName('<dscp_port>')

inet_dscp_port_keyword_and_number_element = (
        Keyword('dscp').suppress()
        + (
            dscp_port('dscp_port')
        )
    # No semicolon here
)('')  # ('dscp_port')

# ip_port = Word(nums).setParseAction(lambda toks: int(toks[0]), max=5)
_ip_port = Regex(r'(6553[0-5]|'
                 r'655[0-2][0-9]|'
                 r'65[0-4][0-9][0-9]|'
                 r'6[0-4][0-9][0-9][0-9]|'
                 r'[1-5][0-9][0-9][0-9][0-9]|'
                 r'[1-9][0-9][0-9][0-9]|'
                 r'[1-9][0-9][0-9]|'
                 r'[1-9][0-9]|'
                 r'[1-9])')
ip_port = _ip_port('ip_port')
ip_port.setName('<ip_port>')

inet_ip_port_keyword_and_number_element = (
        Keyword('port').suppress()
        - ip_port('ip_port')
    # No semicolon here
)('')

inet_ip_port_keyword_and_wildcard_element = (
        Keyword('port').suppress()
        - (
                ip_port('ip_port_w')
                | Literal('*')('ip_port_w')  # TODO: Use 'wildcard_name' to handle quotes/no-quotes '*'
        )('')
) # ('')  # ('ip_port_w')

# ip4s_subnet = Word(nums, min=1, max=2)
_ip4s_subnet = Regex(r'(3[0-2]|'
                     r'[0-2][0-9]|'
                     r'[0-9])')
ip4s_subnet = _ip4s_subnet('')
ip4s_subnet.setName('<ip4_subnet>')

ip4_addr = pyparsing_common.ipv4_address
ip4_addr.setName('<ip4_addr>')

ip4_addr_or_wildcard = (
        wildcard_name
        | ip4_addr
)
ip4_addr_or_wildcard.setName('<ip4_addr_or_wildcard>')

ip4s_prefix = Combine(ip4_addr + '/' - ip4s_subnet)
ip4s_prefix.setName('<ip4subnet>')

# Apparently, pyparsing_common.ipv6_address cannot the following:
#  - do device index suffix of "%eth0" or "%1"
#  - Support IPv4 notation after short or mixed IPv6
#  so we roll our own IPv6 address parser

# Device Index (aka Unix sin6_scope_id) can be 32-bit integer or 64-char readable device name
# _ip6_device_index = r'%([0-9]{1,10})|([a-zA-Z0-9\.\-_]{1,64})'
_ip6_device_index = r'%' + \
                    Combine(
                        Word(nums, min=1, max=10)  # Microsoft Windows
                        | Word(alphanums, min=1, max=63)  # Most *nixes
                    )

########ip6_addr = pyparsing_common.ipv6_address
# " ip6_addr  should match:
# "  IPv6 addresses
# "    zero compressed IPv6 addresses (section 2.2 of rfc5952)
# "    link-local IPv6 addresses with zone index (section 11 of rfc4007)
# "    IPv4-Embedded IPv6 Address (section 2 of rfc6052)
# "    IPv4-mapped IPv6 addresses (section 2.1 of rfc2765)
# "    IPv4-translated addresses (section 2.1 of rfc2765)
# "  IPv4 addresses

# ip6s_subnet = Word(nums, min=1, max=3)
_ip6s_subnet = Regex(r'(12[0-8]|'
                     r'1[0-1][0-9]|'
                     r'[1-9][0-9]|'
                     r'[0-9])')
ip6s_subnet = _ip6s_subnet('ip6s_subnet')
ip6s_subnet.setName('<ip6_subnet>')

_ip6_part = r'[0-9a-fA-F]{1,4}'
_ip6_full_addr = _ip6_part + r':' + \
                 _ip6_part + r':' + \
                 _ip6_part + r':' + \
                 _ip6_part + r':' + \
                 _ip6_part + r':' + \
                 _ip6_part + r':' + \
                 _ip6_part + r':' + \
                 _ip6_part

ip6_part = Regex(_ip6_part).setName('4-hex')
ip6_full_addr = Regex(_ip6_full_addr).setName('<full_ip6_addr>')

# ::
_ip6_0_0_addr = r'::'
ip6_0_0_addr = Regex(_ip6_0_0_addr)
# ::8
_ip6_0_1_addr = r'::' + _ip6_part
ip6_0_1_addr = Regex(_ip6_0_1_addr)
# ::2:3:4:5:6:7:8
_ip6_0_7_addr = r':(:' + _ip6_part + r'){7}'
ip6_0_7_addr = Regex(_ip6_0_7_addr)

# 1::
_ip6_1_0_addr = _ip6_part + r'::'
ip6_1_0_addr = Regex(_ip6_1_0_addr)
# 1::8
_ip6_1_1_addr = _ip6_part + r'::' + _ip6_part
ip6_1_1_addr = Regex(_ip6_1_1_addr)
# 1::7:8
_ip6_1_2_addr = _ip6_part + r':(:' + _ip6_part + r'){2}'
ip6_1_2_addr = Regex(_ip6_1_2_addr)
# 1::6:7:8
_ip6_1_3_addr = _ip6_part + r':(:' + _ip6_part + r'){3}'
ip6_1_3_addr = Regex(_ip6_1_3_addr)
# 1::5:6:7:8
_ip6_1_4_addr = _ip6_part + r':(:' + _ip6_part + r'){4}'
ip6_1_4_addr = Regex(_ip6_1_4_addr)
# 1::4:5:6:7:8
_ip6_1_5_addr = _ip6_part + r':(:' + _ip6_part + r'){5}'
ip6_1_5_addr = Regex(_ip6_1_5_addr)
# 1::3:4:5:6:7:8
_ip6_1_6_addr = _ip6_part + r':(:' + _ip6_part + r'){6}'
ip6_1_6_addr = Regex(_ip6_1_6_addr)

# 1:2::0
_ip6_2_0_addr = r'(' + _ip6_part + ':){2}:'
ip6_2_0_addr = Regex(_ip6_2_0_addr)
# 1:2::8
_ip6_2_1_addr = r'(' + _ip6_part + ':){2}:' + _ip6_part
ip6_2_1_addr = Regex(_ip6_2_1_addr)
# 1:2::4:5:6:7:8
_ip6_2_5_addr = r'(' + _ip6_part + ':){2}(:' + _ip6_part + r'){5}'
ip6_2_5_addr = Regex(_ip6_2_5_addr)

# 1:2:3::
_ip6_3_0_addr = r'(' + _ip6_part + ':){3}:'
ip6_3_0_addr = Regex(_ip6_3_0_addr)
# 1:2:3::8
_ip6_3_1_addr = r'(' + _ip6_part + ':){3}:' + _ip6_part
ip6_3_1_addr = Regex(_ip6_3_1_addr)
# 1:2:3::5:6:7:8
_ip6_3_4_addr = r'(' + _ip6_part + ':){3}(:' + _ip6_part + r'){4}'
ip6_3_4_addr = Regex(_ip6_3_4_addr)

# 1:2:3:4::
_ip6_4_0_addr = r'(' + _ip6_part + ':){4}:'
ip6_4_0_addr = Regex(_ip6_4_0_addr)
# 1:2:3:4::8
_ip6_4_1_addr = r'(' + _ip6_part + ':){4}:' + _ip6_part
ip6_4_1_addr = Regex(_ip6_4_1_addr)
# 1:2:3:4::6:7:8
_ip6_4_3_addr = r'(' + _ip6_part + ':){4}(:' + _ip6_part + r'){3}'
ip6_4_3_addr = Regex(_ip6_4_3_addr)

# 1:2:3:4:5::
_ip6_5_0_addr = r'(' + _ip6_part + ':){5}:'
ip6_5_0_addr = Regex(_ip6_5_0_addr)
# 1:2:3:4:5::8
_ip6_5_1_addr = r'(' + _ip6_part + ':){5}:' + _ip6_part
ip6_5_1_addr = Regex(_ip6_5_1_addr)
# 1:2:3:4:5::7:8
_ip6_5_2_addr = r'(' + _ip6_part + ':){5}(:' + _ip6_part + r'){2}'
ip6_5_2_addr = Regex(_ip6_5_2_addr)

# 1:2:3:4:5:6::
_ip6_6_0_addr = r'(' + _ip6_part + ':){6}:'
ip6_6_0_addr = Regex(_ip6_6_0_addr)
# 1:2:3:4:5:6::8
_ip6_6_1_addr = r'(' + _ip6_part + ':){6}:' + _ip6_part
ip6_6_1_addr = Regex(_ip6_6_1_addr)

# 1:2:3:4:5:6:7::
_ip6_7_0_addr = r'(' + _ip6_part + r':){7}:'
ip6_7_0_addr = Regex(_ip6_7_0_addr)

# 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
_ip6_4_0_ip4_addr = r'(' + _ip6_part + r':){4}:([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_4_0_ip4_addr = Regex(_ip6_4_0_ip4_addr)
_ip6_3_0_ip4_addr = r'(' + _ip6_part + r':){3}:([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_3_0_ip4_addr = Regex(_ip6_3_0_ip4_addr)
_ip6_2_0_ip4_addr = r'(' + _ip6_part + r':){2}:([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_2_0_ip4_addr = Regex(_ip6_2_0_ip4_addr)
# ::ffff:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
_ip6_0_3_ip4_addr = r':(:' + _ip6_part + r'){3}:([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_0_3_ip4_addr = Regex(_ip6_0_3_ip4_addr)
_ip6_0_2_ip4_addr = r':(:' + _ip6_part + r'){2}:([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_0_2_ip4_addr = Regex(_ip6_0_2_ip4_addr)
_ip6_0_1_ip4_addr = r':(:' + _ip6_part + r'){1}:([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_0_1_ip4_addr = Regex(_ip6_0_1_ip4_addr)
# ::255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
_ip6_0_0_ip4_addr = r'::([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_0_0_ip4_addr = Regex(_ip6_0_0_ip4_addr)

# 2001:db8::2:192.0.2.33  (unknown 2-1 combo)
_ip6_2_1_ip4_addr = _ip6_part + r':' + _ip6_part + r'::' + _ip6_part + r':([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_2_1_ip4_addr = Regex(_ip6_2_1_ip4_addr)
# 2001::13f:9:192.8.1.16  (unknown 1-2 combo)
_ip6_1_2_ip4_addr = _ip6_part + r'::' + _ip6_part + r':' + _ip6_part + r':([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_1_2_ip4_addr = Regex(_ip6_1_2_ip4_addr)
# 2001::13f:192.8.1.16  (unknown 1-1 combo)
_ip6_1_1_ip4_addr = _ip6_part + r'::' + _ip6_part + r':([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_1_1_ip4_addr = Regex(_ip6_1_1_ip4_addr)
# 2001::192.8.1.16  (unknown 1-0 combo)
_ip6_1_0_ip4_addr = _ip6_part + r'::([0-9]{1,3}\.){3}[0-9]{1,3}'
ip6_1_0_ip4_addr = Regex(_ip6_1_0_ip4_addr)

_ip6_addr = Combine(
    ip6_4_0_ip4_addr
    | ip6_3_0_ip4_addr
    | ip6_2_1_ip4_addr
    | ip6_2_0_ip4_addr
    | ip6_1_2_ip4_addr
    | ip6_1_1_ip4_addr
    | ip6_1_0_ip4_addr
    | ip6_0_3_ip4_addr
    | ip6_0_2_ip4_addr
    | ip6_0_1_ip4_addr
    | ip6_0_0_ip4_addr
    | ip6_7_0_addr
    | ip6_6_1_addr
    | ip6_6_0_addr
    | ip6_5_2_addr
    | ip6_5_1_addr
    | ip6_5_0_addr
    | ip6_4_3_addr
    | ip6_4_1_addr
    | ip6_4_0_addr
    | ip6_3_4_addr
    | ip6_3_1_addr
    | ip6_3_0_addr
    | ip6_2_5_addr
    | ip6_2_1_addr
    | ip6_2_0_addr
    | ip6_1_6_addr
    | ip6_1_5_addr
    | ip6_1_4_addr
    | ip6_1_3_addr
    | ip6_1_2_addr
    | ip6_1_1_addr
    | ip6_1_0_addr
    | ip6_0_7_addr
    | ip6_0_1_addr
    | ip6_0_0_addr
    | ip6_full_addr
)

ip6_addr = _ip6_addr
ip6_addr.setName('<ip6_addr_only>')

ip6_addr_index = Combine(ip6_addr + _ip6_device_index)
ip6_addr_index.setName('<ip6_addr_with_index_only>')

# fe80::7:8%eth0   (link-local IPv6 addresses with zone index)
# fe80::7:8%1     (link-local IPv6 addresses with zone index)
_ip6_ll_zone_index_addr = _ip6_part + r':(:' + _ip6_part + r'){2}' + _ip6_device_index
ip6_ll_zone_index_addr = _ip6_ll_zone_index_addr

ip6_addr_or_index = Combine(
    ip6_addr + Optional(_ip6_device_index)
    #### | ip6_addr_prefix   # prefix is provided by ip6_addr_prefix
)
ip6_addr_or_index.setName('<ip6_addr_or_device_index>')

ip6s_prefix = Combine(ip6_addr + '/' - ip6s_subnet)
ip6s_prefix.setName('<ip6_with_subnet_only>')

ip6_addr_or_wildcard = (
        wildcard_name
        | ip6_addr
)

# There is no ip46_addr_or_index ... yet

# ip46_addr is just plain addressing (without subnet suffix) for IPv4 and IPv6
ip46_addr = (
        ip4_addr
        | ip6_addr)
ip46_addr.setName('<ip46_addr>')

# ip46_addr_or_prefix is just about every possible IP addressing methods out there
ip46_addr_or_prefix = (
        ip6s_prefix   # strict IPv6 with subnet only; Lookahead via '/'
        | ip4s_prefix   # strict IPv6 with subnet only; Lookahead via '/'
        | ip4_addr    # Lookahead via 'non-hex'
        | _ip6_addr   # no device index here
)
ip46_addr_or_prefix.setName('ip4^ip6^ip4/s^ip6/s')

ip46_addr_or_wildcard = (
        wildcard_name
        | ip4_addr
        | ip6_addr
)
ip46_addr_or_wildcard.setName('<ip_addr_or_wildcard>')

ip46_addr_prefix_or_wildcard = (
        wildcard_name
        | ip4s_prefix
        | ip4_addr
        | ip6_addr
)
ip46_addr_prefix_or_wildcard.setName('<ip46_addr_prefix_or_wildcard>')


### LIST ####
#  Semicolon-terminated section
# Example: 123.123.123.123 ;
ip4_addr_list = Group(
    ip4_addr
    + semicolon
)

# Really want to prevent backtracking after '/' encounter
# because no one else wants IP pattern after this '/'
# Once a dot has been encountered, we know it is not IPv6
# Example: 99.99.99.99/99;
ip4s_prefix_list = ip4s_prefix + semicolon

# Example: 4321::1;
ip6_addr_list = ip6_addr + semicolon

# Used by server-addresses
ip46_addr_list = Group(
    ip46_addr
    + semicolon
)

ip46_addr_and_port_list = (
    (
            ip46_addr('addr')
            + Optional(inet_ip_port_keyword_and_number_element)
            + semicolon
    )('ip46_addr_port')
)('')


### SERIES ####

# 999.999.999.999; [ 999.999.999.999; ]*
ip4_addr_list_series = Group(
    ip4_addr_list
    + ZeroOrMore(ip4_addr_list)
)

# Example: 1.1.1.1/1; 2.2.2.2/2; 3.3.3.3/3;
ip4s_prefix_list_series = Group(
    ip4s_prefix_list
    + ZeroOrMore(ip4s_prefix_list)
)

# Example: 4321::1; 5432::7; 6543::8;
ip6_addr_list_series = Group(
    ip6_addr_list
    + ZeroOrMore(ip6_addr_list)
)

# Example: 3210::3; 1.1.1.1;
ip46_addr_list_series = (
    OneOrMore(ungroup(ip46_addr_list))
    # + ZeroOrMore(ip46_addr_list)
)

# Example: 3210::3; 123.123.123.1/24; 1.1.1.1;
ip_addr_list = ip46_addr_or_prefix + semicolon
ip_addr_semicolon_series = Group(
    ip_addr_list
    + ZeroOrMore(ip_addr_list)
)

