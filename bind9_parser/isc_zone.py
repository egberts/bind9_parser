#!/usr/bin/env python3
"""
File: isc_zone.py

Clause: zone

Title: Statements Used Only By zone Clause

Description: Provides Zone-related grammar in PyParsing engine
             for ISC-configuration style
"""
from pyparsing import Keyword, Group, Literal, CaselessLiteral, OneOrMore,\
    ZeroOrMore, Word, Optional, ungroup, Combine
from bind9_parser.isc_utils import parse_me, semicolon, lbrack, rbrack, path_name,\
    isc_boolean, view_name, isc_file_name,\
    number_type, key_id, check_options, zone_name, acl_name,\
    key_id_keyword_and_name_pair, squote, dquote, dlz_name_type,\
    database_name_type, krb5_realm_name
from bind9_parser.isc_inet import ip46_addr_list_series, ip4_addr,\
    ip6_addr, ip_port, dscp_port, inet_ip_port_keyword_and_number_element,\
    inet_dscp_port_keyword_and_number_element,\
    ip46_addr_and_port_list
from bind9_parser.isc_rr import rr_type_series, rr_type_list_series
from bind9_parser.isc_domain import domain_generic_fqdn,\
    quotable_domain_generic_fqdn, quoted_domain_generic_fqdn, rr_fqdn_w_absolute
from bind9_parser.isc_viewzone import viewzone_stmt_database, viewzone_stmt_dlz
from bind9_parser.isc_clause_masters import clause_stmt_masters_standalone



######## Zone statements #############################################
zone_stmt_check_names = (
    Keyword('check-names').suppress()
    - check_options('check_names')
    + semicolon
)

database_arg = path_name
zone_stmt_database_former = (
    Keyword('database').suppress()
    - Group(
        path_name
        - ZeroOrMore(
            database_arg('arg')
        )('args')
    )('')
    + semicolon
)('database')

zone_stmt_delegation_only = (
    Keyword('delegation-only').suppress()
    - isc_boolean('delegation-only')
    + semicolon
)

zone_stmt_file = (
    Keyword('file').suppress()
    - path_name('file')
    + semicolon
)

zone_stmt_in_view = (
    Keyword('in-view').suppress()
    - view_name('in_view')
    + semicolon
)

zone_stmt_inline_signing = (
    Keyword('inline-signing').suppress()
    - isc_boolean('inline-signing')
    + semicolon
)

# ixfr-base got obsoleted; 9.15.0 doesn't have it, might be before
zone_stmt_ixfr_base = (
    Keyword('ixfr-base').suppress()
    - isc_file_name('ixfr_base')
    + semicolon
)

zone_stmt_ixfr_from_differences = (
    Keyword('ixfr-from-differences').suppress()
    - isc_boolean('ixfr_from_differences')
    + semicolon
)

zone_stmt_journal = (
    Keyword('journal').suppress()
    - path_name('journal')
    + semicolon
)

# masters
# Note: Not the same syntax as clause_stmt_masters_series
#
# Only found in zone-stub or zone-slave
# masters [ port integer ] [ dscp integer ]
#         {
#             ( masters
#               | ipv4_address [ port integer ]
#               | ipv6_address [ port integer ]
#             )
#             [ key string ]
#             ;
#             ...
#         };
master_name = key_id  # TODO make a master type here (instead of key_id)
zone_masters_set = (
    (
        (
            ungroup(
                    ip4_addr
                    - Optional(inet_ip_port_keyword_and_number_element('ip_port'))
            )('ip4')
            ^ ungroup(
                    ip6_addr
                    - Optional(inet_ip_port_keyword_and_number_element('ip_port'))
            )('ip6')
            ^ master_name('master_name')
        )('')
        - Optional(key_id_keyword_and_name_pair)
    )('')
    + semicolon
)('')

zone_masters_series = (
    OneOrMore(
        Group(
            zone_masters_set('')
        )('')
    )('masters_group')
)

# 'masters' clause has a name field for the 1st argument;
#     'masters' statement in the zone clause does not
zone_stmt_masters = (
    Group(
        Keyword('masters').suppress()
        + Optional(inet_ip_port_keyword_and_number_element)
        - Optional(inet_dscp_port_keyword_and_number_element)
        - lbrack
        - zone_masters_series
        + rbrack
    )('masters')
    + semicolon
)

# pubkey number number number string; [ Zone ]
# The DNSSEC flags, protocol, and algorithm are specified, as well as a base-64 encoded string representing the key.
pubkey_flags = number_type
pubkey_protocol = number_type
pubkey_algorithm = number_type
# Secret are in base64 encoding scheme with 2-char paddings (RFC 1421)
# Handles up to 16K encoding
pubkey_secret_type = Word('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', max=16383)
pubkey_secret_type.setName('<key-secret>')

# secret <string>;
pubkey_secret = (
    Combine(squote.suppress() + pubkey_secret_type + squote.suppress())
    | Combine(dquote.suppress() + pubkey_secret_type + dquote.suppress())
)

# pubkey is obsoleted since 9.0.0
zone_stmt_pubkey = (
    Keyword('pubkey').suppress()
    - Group(
        pubkey_flags('flags')
        - pubkey_protocol('protocol')
        - Optional(pubkey_algorithm('algorithms'))
        - Optional(pubkey_secret('key_secret'))
    )('pubkey')
    + semicolon
)

#   server-addresses server-addresses {ip-address; [...;]}; [ Zone ] [Def=N/A]
#   Only used if zone type is 'static-stub'
zone_stmt_server_addresses = (
    Keyword('server-addresses').suppress()
    + (
        lbrack
        - OneOrMore(
            Group(
                ip46_addr_and_port_list
            )('')
        )('')
        + rbrack
    )('')
    + semicolon
)('server_addresses')

quoted_rr_fqdn_w_absolute = (
    Combine(squote.suppress() + rr_fqdn_w_absolute + squote.suppress())
    | Combine(dquote.suppress() + rr_fqdn_w_absolute + dquote.suppress())
)

zone_stmt_server_names = (
    Keyword('server-names').suppress()
    - (
        lbrack
        - OneOrMore(
            quoted_rr_fqdn_w_absolute
            + semicolon
        )('')
        + rbrack
    )('server_names')
    + semicolon
)('')
# type zone_type; [ Zone ]
zone_stmt_type = (
    Keyword('type').suppress()
    - (
        Literal('delegation-only')
        | Literal('forward')
        | Literal('hint')
        | Literal('in-view')  # Not < 9.1
        | (
            Literal('master')
            | Literal('primary')
        )
        | Literal('redirect')
        | (
            Literal('slave')
            | Literal('secondary')
        )
        | Literal('static-stub')
        | Literal('stub')
    )('type')
    + semicolon
)

# update-policy-rule permission identity matchtype [tname] [rr]
zone_update_policy_permission = (
    CaselessLiteral('grant')
    | CaselessLiteral('deny')
)

zone_update_policy_identity = (quotable_domain_generic_fqdn | Literal('*'))('identity')
zone_update_policy_name_field = quotable_domain_generic_fqdn('name_type')
zone_update_policy_principal_field = krb5_realm_name('name_type')

zone_update_policy_rr_type_series = (
    (
        CaselessLiteral('any')
        | Literal('*')
        | rr_type_series
    )
)

zone_update_policy_name_and_rr_type_fields = (
        zone_update_policy_name_field('impacting_zone')
        - zone_update_policy_rr_type_series('rr_types')
)

zone_update_policy_principal_and_rr_type_fields = (
        zone_update_policy_principal_field('impacting_realm')
        - zone_update_policy_rr_type_series('rr_types')
)

# Why did I break out this krb5_self syntax?  For further refinement and debugging
zone_update_policy_matchtype_krb5_self = (
    Keyword('krb5-self')('policy')
    - zone_update_policy_principal_and_rr_type_fields('')
)

zone_update_policy_matchtype = (
    zone_update_policy_matchtype_krb5_self
    | (Keyword('krb5-subdomain')('policy') - zone_update_policy_principal_and_rr_type_fields)
    | (Keyword('ms-self')('policy') - zone_update_policy_principal_and_rr_type_fields)
    | (Keyword('ms-subdomain')('policy') - zone_update_policy_principal_and_rr_type_fields)

    | (Keyword('8to6-self')('policy') - ungroup(zone_update_policy_name_and_rr_type_fields))
    | (Keyword('external')('policy') - zone_update_policy_name_and_rr_type_fields)
    | (Keyword('name')('policy') - zone_update_policy_name_and_rr_type_fields)
    | (Keyword('self')('policy') - zone_update_policy_name_and_rr_type_fields)
    | (Keyword('selfsub')('policy') - zone_update_policy_name_and_rr_type_fields)
    | (Keyword('selfwildcard')('policy') - zone_update_policy_name_and_rr_type_fields)
    | (Keyword('tcp-self')('policy') - zone_update_policy_name_and_rr_type_fields)
    | (Keyword('wildcard')('policy') - zone_update_policy_name_and_rr_type_fields)

    | (Keyword('zonesub')('policy') - zone_update_policy_rr_type_series)
    | (Keyword('subdomain')('policy') - zone_update_policy_rr_type_series)
)('')


zone_stmt_update_policy_nonlocal = (
    (
        zone_update_policy_permission('permission')
        - zone_update_policy_identity('requestor_domain')
        - zone_update_policy_matchtype('')
        + semicolon
    )
)('')  # no label here, we're floating this syntax group up by an other referencer

zone_stmt_update_policy_nonlocal_series = OneOrMore(zone_stmt_update_policy_nonlocal)

# update-policy (local
#                | {
#                    (deny | grant)
#                    string(
#                        6to4-self
#                        | external
#                        | krb5-self
#                        | krb5-selfsub
#                        | krb5-subdomain
#                        | ms-self
#                        | ms-selfsub
#                        | ms-subdomain
#                        | name
#                        | self
#                        | selfsub
#                        | selfwild
#                        | subdomain
#                        | tcp-self
#                        | wildcard
#                        | zonesub )
#                    [string]
#                    rrtypelist ;
#                    ...};

# update-policy { update_policy_rule [...] }; [ Zone ]
zone_stmt_update_policy = (
     Keyword('update-policy').suppress()
     + (
         Literal('local')
         | OneOrMore(
             lbrack
             - Group(
                 zone_stmt_update_policy_nonlocal_series
             )
             + rbrack
             + semicolon
         )
     )('update_policy')
)
#     + lbrack
#     + zone_update_policy_permission
#     + zone_update_policy_identity
#     + zone_update_policy_matchtype
#     + Optional(rr_domain_name_or_wildcard_type)
#     + Optional(zone_update_policy_rr)
#     + semicolon
#     + rbrack
#     + semicolon
# )

#  use-id-pool <boolean>;  [ Zone ]  # v8.2 to v9.7.0; still inert
zone_stmt_use_id_pool = (
    Keyword('use-id-pool').suppress()
    - isc_boolean('use_id_pool')
    + semicolon
)

################### Multiple-statement ##########################
zone_multiple_stmt_masters = (
    ZeroOrMore(
        (
            zone_stmt_masters('')  # blank this label so that a multiple group can assume this label
        )('')
    )('masters')
)

# Keywords are in dictionary-order, but with longest pattern as having been listed firstly
zone_statements_set = (
    zone_stmt_check_names
    | zone_stmt_delegation_only
    | zone_stmt_file
    | zone_stmt_in_view
    | zone_stmt_inline_signing
    | zone_stmt_ixfr_base
    | zone_stmt_ixfr_from_differences
    | zone_stmt_journal
###    | zone_stmt_masters
    | zone_stmt_pubkey
    | zone_stmt_server_addresses
    | zone_stmt_server_names
    | zone_stmt_type
    | zone_stmt_update_policy
    | zone_stmt_use_id_pool
    | clause_stmt_masters_standalone('masters')  # exactly ONE 'masters' allowed within each zone.
)

zone_statements_series = (
    OneOrMore(
            zone_statements_set('')
    )('')
)
