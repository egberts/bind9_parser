#!/usr/bin/env python3
"""
File: isc_rr.py

Element: rr

Title: Elements That Provides DNS Resource Records

Description: Provides RR-related grammar in PyParsing engine
             for ISC-configuration style

             For resource records found in BIND9 DNS zone records
"""

from pyparsing import Optional, Combine, CaselessLiteral, \
    Literal, Char, OneOrMore, Group, ungroup
from bind9_parser.isc_utils import semicolon
from bind9_parser.isc_domain import domain_generic_fqdn, domain_charset_wildcard


g_test_over_63_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc"

rr_class_in = CaselessLiteral('IN')
rr_class_ch = CaselessLiteral('CH')
rr_class_hesiod = CaselessLiteral('HS')
rr_class_none = CaselessLiteral('NONE')  # RFC 2136
rr_class_any = CaselessLiteral('ANY')  # RFC 1035

rr_class_set = (
    rr_class_in
    | rr_class_hesiod
    | rr_class_ch
    | rr_class_none
    | rr_class_any
)('rr_class')
rr_class_set.setName('<rr_class>')

rr_type_a = CaselessLiteral('A')
rr_type_ns = CaselessLiteral('NS')
rr_type_cname = CaselessLiteral('CNAME')
rr_type_soa = CaselessLiteral('SOA')
rr_type_wks = CaselessLiteral('WKS')
rr_type_ptr = CaselessLiteral('PTR')
rr_type_hinfo = CaselessLiteral('HINFO')
rr_type_mx = CaselessLiteral('MX')
rr_type_txt = CaselessLiteral('TXT')
rr_type_x25 = CaselessLiteral('X25')
rr_type_aaaa = CaselessLiteral('AAAA')
rr_type_location = CaselessLiteral('LOC')
rr_type_srv = CaselessLiteral('SRV')
rr_type_ds = CaselessLiteral('DS')
rr_type_rrsig = CaselessLiteral('RRSIG')
rr_type_nsec = CaselessLiteral('NSEC')
rr_type_dnskey = CaselessLiteral('DNSKEY')
rr_type_nsec3 = CaselessLiteral('NSEC3')
rr_type_nsec3param = CaselessLiteral('NSEC3PARAM')
rr_type_tlsa = CaselessLiteral('TLSA')
rr_type_openpgpkey = CaselessLiteral('OPENPGPKEY')
rr_type_tkey = CaselessLiteral('TKEY')
rr_type_tsig = CaselessLiteral('TSIG')
rr_type_caa = CaselessLiteral('CAA')

rr_type_set = ungroup(
   rr_type_aaaa
   | rr_type_a
   | rr_type_caa
   | rr_type_cname
   | rr_type_dnskey
   | rr_type_ds
   | rr_type_hinfo
   | rr_type_location
   | rr_type_mx
   | rr_type_nsec3param
   | rr_type_nsec3
   | rr_type_nsec
   | rr_type_ns
   | rr_type_openpgpkey
   | rr_type_ptr
   | rr_type_rrsig
   | rr_type_soa
   | rr_type_srv
   | rr_type_tkey
   | rr_type_tlsa
   | rr_type_tsig
   | rr_type_txt
   | rr_type_wks
   | rr_type_x25
)('rr_type')
rr_type_set.setName('<rr_type>')

#  a series of RR types (without a semicolon separator)
rr_type_series = OneOrMore(
        rr_type_set('')  # remove this label so we can float result to a bigger, later label
)('rr_types')
rr_type_series.setName('<rr_type ...>')

#  a series of RR types (with a semicolon separator)
rr_type_list_series = OneOrMore(
    rr_type_set
    + semicolon
)('rr_type_list')
rr_type_list_series.setName('<rr_type; ...;>')

#  Following is commonly used in association with DNS zone records
rr_fqdn_w_absolute = Combine(
    domain_generic_fqdn
    + Optional(Literal('.'))
)
rr_fqdn_w_absolute.setName('<rr_fqdn_with_abs>')

# rr_domain_name is uzed in association with DNS zone records
# by 'update-policy', a zone-specific option
rr_domain_name = Combine(
    domain_generic_fqdn
    + Optional(Literal('.'))
)
rr_domain_name.setName('<rr_domain_name>')

# rr_domain_name may be '*.example.net', '*.congress.gov.', or '*'
rr_domain_name_or_wildcard = (
        rr_domain_name
        | Char(domain_charset_wildcard)
)
rr_domain_name_or_wildcard.setName('<target_rr_name>')

#  ( <fqdn> | '.' )
rr_domain_name_or_root = (
rr_domain_name
    | Literal('.')
)
rr_domain_name_or_root.setName('<rr_domain_or_root>')
