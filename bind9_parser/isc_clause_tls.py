#!/usr/bin/env python3
"""
File: isc_clause_tls.py

Clause: tls

Title: Clause statement for 'tls'

Description: 

  Statement Grammar:

    tls string {
        ca-file <quoted_string>;
        cert-file <quoted_string>;
        ciphers <string>;
        dhparam-file <quoted_string>;
        key-file <quoted_string>;
        prefer-server-ciphers <boolean>;
        protocols { <string>; ... };
        remote-hostname <quoted_string>;
        session-tickets <boolean>;
    };

"""
from pyparsing import Group, Keyword, ZeroOrMore, OneOrMore
from bind9_parser.isc_utils import semicolon, \
    fqdn_name, \
    lbrack, rbrack, dequoted_path_name, isc_boolean, \
    dequotable_name

# NOTE: If any declaration here is to be used OUTSIDE of 
# the 'tls' clause, it should instead be defined within isc_utils.py

tls_stmt_ca_file_element = (
                Keyword('ca-file').suppress()
                + dequoted_path_name('ca_file')
                + semicolon
            )

tls_stmt_cert_file_element = (
                Keyword('cert-file').suppress()
                + dequoted_path_name('cert_file')
                + semicolon
            )

tls_stmt_ciphers_element = (
                Keyword('ciphers').suppress()
                + dequotable_name('ciphers')
                + semicolon
            )

tls_stmt_dhparam_file_element = (
                Keyword('dhparam-file').suppress()
                + dequoted_path_name('dhparam_file')
                + semicolon
            )

tls_stmt_key_file_element = (
                Keyword('key-file').suppress()
                + dequoted_path_name('key_file')
                + semicolon
            )

tls_stmt_prefer_server_ciphers_element = (
                Keyword('prefer-server-ciphers').suppress()
                + isc_boolean('prefer_server_ciphers')
                + semicolon
            )

"""         protocols { <string>; ... };  """
tls_stmt_protocols_element = (
    Keyword('protocols').suppress()
    + Group(
        lbrack
        + OneOrMore(
            dequotable_name('*')
            + semicolon
        )
        + rbrack
    )('protocols')
    + semicolon
)

tls_stmt_remote_hostname_element = (
    Keyword('remote-hostname').suppress()
    + fqdn_name('remote_hostname')
    + semicolon
)

tls_stmt_session_tickets_element = (
    Keyword('session-tickets').suppress()
    + isc_boolean('session_tickets')
    + semicolon
)

"""
    tls string {
        ca-file <quoted_string>;
        cert-file <quoted_string>;
        ciphers <string>;
        dhparam-file <quoted_string>;
        key-file <quoted_string>;
        prefer-server-ciphers <boolean>;
        protocols { <string>; ... };
        remote-hostname <quoted_string>;
        session-tickets <boolean>;
    };
"""

tls_stmt_element_set = (
            tls_stmt_ca_file_element
            | tls_stmt_cert_file_element
            | tls_stmt_ciphers_element
            | tls_stmt_dhparam_file_element
            | tls_stmt_key_file_element
            | tls_stmt_prefer_server_ciphers_element
            | tls_stmt_protocols_element
            | tls_stmt_remote_hostname_element
            | tls_stmt_session_tickets_element
)

tls_stmt_element_series = (
    OneOrMore(tls_stmt_element_set)
)

clause_stmt_tls_standalone = (
        Keyword('tls').suppress()
        + Group(
            dequotable_name('tls_name')
            + lbrack
            + OneOrMore(tls_stmt_element_series)
            + rbrack
        )('tls*')
        + semicolon
)
clause_stmt_tls_standalone.setName(
    'tls <string> { ca-file <string>; cert-file <string>; ciphers <string>; '
    + 'dhparam-file <quoted_string>; prefer-server-ciphers <boolean>; '
    + 'protocols { <string>; ... }; remote-hostname <quoted_string>; session-tickets <boolean>; };')

clause_stmt_tls_set = clause_stmt_tls_standalone
clause_stmt_tls_standalone.setName(
    """tls <string> { 
    ca-file <string>; 
    cert-file <string>; 
    ciphers <string>; 
    dhparam-file <quoted_string>; 
    prefer-server-ciphers <boolean>; 
    protocols { <string>; ... }; 
    remote-hostname <quoted_string>; 
    session-tickets <boolean>; 
};""")

# {0-*} statement
clause_stmt_tls_series = ZeroOrMore(clause_stmt_tls_set)
clause_stmt_tls_series.setName('tls <string> { ... }; ...')
