#!/usr/bin/env python3.7
"""
File: test_view.py

Clause: view

Title: Statements Used Only By view Clause.

Description: Provides view-related grammar in PyParsing engine
             for ISC-configuration style
"""
import unittest
from pyparsing import cppStyleComment, pythonStyleComment
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_view import \
    clause_stmt_view_standalone,\
    clause_stmt_view_series,\
    view_all_statements_set,\
    view_all_statements_series


class TestClauseView(unittest.TestCase):
    """ Clause view """

    def test_isc_clause_view_zone_passing(self):
        """ Clause view; Statement zone; passing mode """
        test_data = [
            'view red { zone www.example.com { auto-dnssec maintain; }; };',
        ]
        result = clause_stmt_view_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_view_zone_dict_passing(self):
        assertParserResultDictTrue(
            clause_stmt_view_standalone,
            'view red IN { zone www.example.com { auto-dnssec maintain; }; };',
            {'view': [{'configs': {'zone': {'auto_dnssec': 'maintain',
                                             'zone_name': 'www.example.com'}},
                       'rr_class': 'IN',
                       'view_name': 'red'}]}
        )

    def test_isc_clause_view_passing(self):
        test_data = [
            """ view chaos { match-clients { any; }; zone "bind" { type master; file "/var/lib/bind/internal/master/db.bind"; allow-update { none; }; allow-transfer { none; }; }; };""",
            'view xyz { database this_one; dlz that_one; };'
            ]
        test_clause_stmt_view = clause_stmt_view_standalone.copy()
        test_clause_stmt_view = test_clause_stmt_view.setWhitespaceChars(' \t')
        test_clause_stmt_view = test_clause_stmt_view.ignore(pythonStyleComment)
        test_clause_stmt_view = test_clause_stmt_view.ignore(cppStyleComment)
#        test_clause_stmt_view.ignore(pythonStyleComment)
#        test_clause_stmt_view.ignore(cppStyleComment)
        result = clause_stmt_view_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_view_dict_passing(self):
        assertParserResultDictTrue(
            clause_stmt_view_series,
            'view red { match-clients { any; }; };' +
            'view green { database those_are; };',
            {'view': [{'configs': {'match_clients': {'aml': [{'addr': 'any'}]}},
                       'view_name': 'red'},
                      {'configs': {'database': 'those_are'},
                       'view_name': 'green'}]}
        )
    def test_isc_clause_view_statements_series_passing(self):
        test_data = [""" zone "home" IN { type master; file "/var/lib/bind/internal/master/db.home"; allow-update { none; }; };"""]
        result = view_all_statements_series.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_view_all_statements_series_passing(self):
        test_data = """
    match-clients { trusted_cablesupport_acl; };
    allow-query {
        trusted_cablesupport_acl;
        };
    recursion yes;
    allow-recursion { trusted_cablesupport_acl; };
    allow-query-cache { trusted_cablesupport_acl; };
    allow-transfer { none; };
    allow-update { none; };
    database this_database_name;
    dlz given_database_zone;
    empty-zones-enable no;
    disable-empty-zone yes;
    forwarders {
        71.242.0.12;
        71.252.0.12;
        };
    trusted-keys { "example.net." 243 1 3 "ASDASDASDASD+ASDASDASDASD/ASDASDASSD=="; };
    zone "home" IN {
        type master;
        file "/var/lib/bind/internal/master/db.home";
        allow-update { none; };
        };
    zone "1.168.192.in-addr.arpa" IN {
        type master;
        file "/var/lib/bind/internal/master/db.ip4.1.168.192";
        allow-update {
            key DDNS_UPDATER;
            };
        forwarders { };
        notify no;
        };
    zone "localhost" IN {
        type master;
        file "/var/lib/bind/internal/master/db.localhost";
        allow-update { none; };
        forwarders { };
        notify no;
        };
    zone "0.0.127.in-addr.arpa" IN {
        type master;
        file "/var/lib/bind/internal/master/db.ip4.127";
        allow-update { none; };
        forwarders { };
        notify no;
        };
    zone "." IN {
        type hint;
        delegation-only yes;
        file "/var/lib/bind/internal/master/db.cache.home";
        };
    """
    # view_all_statements_series.
        assertParserResultDictTrue(
            view_all_statements_series,
            test_data,
            {'allow-recursion': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'allow_query': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'allow_query_cache': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'allow_transfer': {'aml': [{'addr': 'none'}]},
             'allow_update': {'aml': [{'addr': 'none'}]},
             'database': 'this_database_name',
             'disable_empty_zone': [{'zone_name': 'yes'}],
             'dlz': 'given_database_zone',
             'empty_zones_enable': 'no',
             'fowarders': [{'fwdr2': [{'addr': '71.242.0.12'},
                                      {'addr': '71.252.0.12'}]}],
             'match_clients': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'recursion': 'yes',
             'trusted_keys': [{'algorithm_id': 3,
                               'domain': 'example.net.',
                               'flags': 243,
                               'protocol_id': 1}],
             'zone': {'delegation-only': 'yes',
                       'file': '"/var/lib/bind/internal/master/db.cache.home"',
                       'type': 'hint',
                       'zone_name': '"."'}}
        )


if __name__ == '__main__':
    unittest.main()
