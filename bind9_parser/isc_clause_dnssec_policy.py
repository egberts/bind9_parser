#!/usr/bin/env python3
"""
File: isc_clause_dnssecpolicy.py

Clause: dnssec-policy

Title: Clause statement for DNSSEC Policies

Description: 
    dnssec-policy standard {
        dnskey-ttl 600;
        keys {
            ksk lifetime 365d algorithm ecdsap256sha256;
            zsk lifetime 60d algorithm ecdsap256sha256;
        };
        max-zone-ttl 600;
        parent-ds-ttl 600;
        parent-propagation-delay 2h;
        publish-safety 7d;
        retire-safety 7d;
        signatures-refresh 5d;
        signatures-validity 15d;
        signatures-validity-dnskey 15d;
        zone-propagation-delay 2h;
    };
"""
from pyparsing import Word, alphanums, Group, Keyword, ZeroOrMore, OneOrMore, Optional, nums
from bind9_parser.isc_utils import semicolon, lbrack, rbrack, iso8601_duration, name_base,\
    isc_file_name, lbrack, rbrack, quoted_path_name

# NOTE: If any declaration here is to be used OUTSIDE of 
# the 'dnssec-policy' clause, it should instead be defined in isc_utils.py

dnssecpolicy_dnskey_ttl_element = (
        Keyword('dnskey-ttl').suppress()
        - iso8601_duration('dnskey_ttl')
        + semicolon
).setName('dnskey-ttl <duration>;')

dnssecpolicy_keys_type = (
    Keyword('csk')
    | Keyword('ksk')
    | Keyword('zsk')
)

"""
        keys {
            ksk lifetime 365d algorithm ecdsap256sha256;
            zsk lifetime 60d algorithm ecdsap256sha256;
        };
"""
dnssecpolicy_keys_element = (
        Keyword('keys').suppress()
        + lbrack
        + Group (
            dnssecpolicy_keys_type('type')
            - Optional(quoted_path_name('key_directory'))
            + Group (
                Keyword('lifetime').suppress()
                + (
                    iso8601_duration
                    | Keyword('unlimited')
                )
            )('lifetime')
            + Group (
                Keyword('algorithm').suppress()
                - name_base('algorithm_name')
                - Optional( Word(nums, min=1, max=9)('algorithm_size') )
            )('algorithm')
            + semicolon
        )('keys*')
        + rbrack
        + semicolon
).setName('keys { [ csk|zsk|ksk ] lifetime <duration algorithm <algo_name> [<algo_size>] };')

dnssecpolicy_max_zone_ttl_element = (
        Keyword('max-zone-ttl').suppress()
        - iso8601_duration('max_zone_ttl')
        + semicolon
).setName('max-zone-ttl <iso8601_duration>;')

dnssecpolicy_salt_len = Word(nums, min=128, max=8192)

dnssecpolicy_nsec3param_element = (
    Keyword('nsec3param').suppress()
    - OneOrMore (
        Group (
            Keyword('iterations').suppress()
            + iso8601_duration('nsec3param_iterations')
        )
        | Group (
            Keyword('iterations').suppress()
            + iso8601_duration('nsec3param_iterations')
         )
        | Group (
            Keyword('salt-length').suppress()
            + dnssecpolicy_salt_len('salt_length')
        )
    )
    + semicolon
).setName('nsec3param [ iterations <integer> ] [ optout <boolean> ] [ salt-length <integer> ];')

dnssecpolicy_parent_ds_ttl_element = (
        Keyword('parent-ds-ttl').suppress()
        - iso8601_duration('parent_ds_ttl')
        + semicolon
).setName('parent-ds-ttl <iso8601_duration>;')

dnssecpolicy_parent_propagation_delay_element = (
    Keyword('parent-propagation-delay').suppress()
    - iso8601_duration('parent_propagation_delay')
    + semicolon
).setName('parent-propagation-delay <iso8601_duration>;')

dnssecpolicy_publish_safety_element = (
    Keyword('publish-safety').suppress()
    - iso8601_duration('publish_safety')
    + semicolon
).setName('publish-safety <iso8601_duration>;')

dnssecpolicy_retire_safety_element = (
    Keyword('retire-safety').suppress()
    - iso8601_duration('retire_safety')
    + semicolon
).setName('retire-safety <iso8601_duration>;')

dnssecpolicy_signatures_refresh_element = (
    Keyword('signatures-refresh').suppress()
    - iso8601_duration('signatures_refresh')
    + semicolon
).setName('signatures-refresh <iso8601_duration>;')

dnssecpolicy_signatures_validity_element = (
    Keyword('signatures-validity').suppress()
    - iso8601_duration('signatures_validity')
    + semicolon
).setName('signatures-validity <iso8601_duration>;')

dnssecpolicy_signatures_validity_dnskey_element = (
    Keyword('signatures-validity-dnskey').suppress()
    - iso8601_duration('signatures_validity_dnskey')
    + semicolon
).setName('signatures-validity-dnskey <iso8601_duration>;')

dnssecpolicy_zone_propagation_delay_element = (
    Keyword('zone-propagation-delay').suppress()
    - iso8601_duration('zone_propagation_delay')
    + semicolon
).setName('zone-propagation <iso8601_duration>;')

# dnssec-policy standard {
#     dnskey-ttl 600;
#     keys {
#         ksk lifetime 365d algorithm ecdsap256sha256;
#         zsk lifetime 60d algorithm ecdsap256sha256;
#     };
#     max-zone-ttl 600;
#     parent-ds-ttl 600;
#     parent-propagation-delay 2h;
#     publish-safety 7d;
#     retire-safety 7d;
#     signatures-refresh 5d;
#     signatures-validity 15d;
#     signatures-validity-dnskey 15d;
#     zone-propagation-delay 2h;
# };
clause_stmt_dnssecpolicy_standalone = (
    Keyword('dnssec-policy').suppress()
    - Group(
        name_base('dnssec_policy_name')
        + lbrack
        - OneOrMore(
            dnssecpolicy_dnskey_ttl_element
            | dnssecpolicy_keys_element
            | dnssecpolicy_max_zone_ttl_element
            | dnssecpolicy_parent_ds_ttl_element
            | dnssecpolicy_parent_propagation_delay_element
            | dnssecpolicy_publish_safety_element
            | dnssecpolicy_retire_safety_element
            | dnssecpolicy_signatures_refresh_element
            | dnssecpolicy_signatures_validity_element
            | dnssecpolicy_signatures_validity_dnskey_element
            | dnssecpolicy_zone_propagation_delay_element
        )
        + rbrack
    )('dnssec_policy*')
    + semicolon
)

clause_stmt_dnssecpolicy_set = clause_stmt_dnssecpolicy_standalone

# {0-*} statement
clause_stmt_dnssecpolicy_series = (
    ZeroOrMore(
        clause_stmt_dnssecpolicy_standalone
    )
)
clause_stmt_dnssecpolicy_series.setName('dnssec-policy <name> { ... };')

