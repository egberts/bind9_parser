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
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_clause_view import \
    clause_stmt_view_standalone,\
    clause_stmt_view_series,\
    view_all_statements_set,\
    view_all_statements_series


class TestClauseView(unittest.TestCase):
    """ Clause view """

    def test_isc_clause_view_zone_passing(self):
        """ Clause view; Statement zone; passing mode """
        test_string = """view red { zone www.example.com { auto-dnssec maintain; }; };"""
        expected_result = { 'views': [ { 'view_name': 'red',
               'zones': [ { 'auto_dnssec': 'maintain',
                            'zone_name': 'www.example.com'}]}]}
        assert_parser_result_dict_true(clause_stmt_view_standalone, test_string, expected_result)

    def test_isc_clause_view_zone_standalone_one_view_passing(self):
        """ Clause view; Statement standalone one-view; passing """
        assert_parser_result_dict_true(
            clause_stmt_view_standalone,
            'view red IN { zone www.example.com { auto-dnssec maintain; }; };',
            {'views': [{'class': 'IN',
                        'view_name': 'red',
                        'zones': [{'auto_dnssec': 'maintain',
                                   'zone_name': 'www.example.com'}]}]}
        )

    def test_isc_clause_view__series_two_view_passing(self):
        """ Clause view; Statement standalone two-view; passing """
        test_string = """
view chaos { 
    match-clients { any; }; 
    zone "bind" {
        type master; 
        file "/var/lib/bind/internal/master/db.bind"; 
        allow-update { none; }; 
        allow-transfer { none; }; 
    };
};
view xyz { database this_one; dlz that_one; }; """
        expected_result = { 'views': [ { 'match_clients': {'aml': [{'keyword': 'any'}]},
               'view_name': 'chaos',
               'zones': [ { 'allow_transfer': { 'aml': [ { 'keyword': 'none'}]},
                            'allow_update': { 'aml': [ { 'keyword': 'none'}]},
                            'file': '/var/lib/bind/internal/master/db.bind',
                            'type': 'master',
                            'zone_name': 'bind'}]},
             { 'database': 'this_one',
               'dlz': 'that_one',
               'view_name': 'xyz'}]}
        assert_parser_result_dict_true(
            clause_stmt_view_series,
            test_string,
            expected_result)

    def test_isc_clause_view_series_3_views_passing(self):
        """ Clause view; Statement series three-view; passing """
        assert_parser_result_dict_true(
            clause_stmt_view_series,
            'view red { match-clients { any; }; };' +
            'view green { database those_are; };',
            {'views': [{'match_clients': {'aml': [{'keyword': 'any'}]},
                        'view_name': 'red'},
                       {'database': 'those_are', 'view_name': 'green'}]}
        )

    def test_isc_clause_view_statements_series_single_passing(self):
        """ Clause view; All Statement series single-view; passing """
        test_string = """
zone "home" IN {
    type master;
    file "/var/lib/bind/internal/master/db.home";
    allow-update { none; };
};"""
        expected_result = { 'zones': [ { 'allow_update': {'aml': [{'keyword': 'none'}]},
               'class': 'IN',
               'file': '/var/lib/bind/internal/master/db.home',
               'type': 'master',
               'zone_name': 'home'}]}
        assert_parser_result_dict_true(view_all_statements_series, test_string, expected_result)

    def test_isc_view_all_statements_series_passing(self):
        """ Clause View; All Statement series; passing """
        test_string = """
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
    trusted-keys { "example.net." 243 1 3 "ASDASDASDASD+ASDASDASDASD/ASDASDASSD"; };
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
        assert_parser_result_dict_true(
            view_all_statements_series,
            test_string,
            {'allow-recursion': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'allow_query': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'allow_query_cache': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'allow_transfer': {'aml': [{'keyword': 'none'}]},
             'allow_update': {'aml': [{'keyword': 'none'}]},
             'database': 'this_database_name',
             'disable_empty_zone': [{'zone_name': 'yes'}],
             'dlz': 'given_database_zone',
             'empty_zones_enable': 'no',
             'forwarders': {'forwarder': [{'ip_addr': '71.242.0.12'},
                                          {'ip_addr': '71.252.0.12'}]},
             'match_clients': {'aml': [{'acl_name': 'trusted_cablesupport_acl'}]},
             'recursion': 'yes',
             'trusted_keys': [{'algorithm_id': '3',
                               'domain': '"example.net."',
                               'key_id': '243',
                               'protocol_type': '1',
                               'pubkey_base64': 'ASDASDASDASD+ASDASDASDASD/ASDASDASSD'}],
             'zones': [{'allow_update': {'aml': [{'keyword': 'none'}]},
                        'class': 'IN',
                        'file': '/var/lib/bind/internal/master/db.home',
                        'type': 'master',
                        'zone_name': 'home'},
                       {'allow_update': {'aml': [{'key_id': ['DDNS_UPDATER']}]},
                        'class': 'IN',
                        'file': '/var/lib/bind/internal/master/db.ip4.1.168.192',
                        'forwarders': [],
                        'notify': 'no',
                        'type': 'master',
                        'zone_name': '1.168.192.in-addr.arpa'},
                       {'allow_update': {'aml': [{'keyword': 'none'}]},
                        'class': 'IN',
                        'file': '/var/lib/bind/internal/master/db.localhost',
                        'forwarders': [],
                        'notify': 'no',
                        'type': 'master',
                        'zone_name': 'localhost'},
                       {'allow_update': {'aml': [{'keyword': 'none'}]},
                        'class': 'IN',
                        'file': '/var/lib/bind/internal/master/db.ip4.127',
                        'forwarders': [],
                        'notify': 'no',
                        'type': 'master',
                        'zone_name': '0.0.127.in-addr.arpa'},
                       {'class': 'IN',
                        'delegation-only': 'yes',
                        'file': '/var/lib/bind/internal/master/db.cache.home',
                        'type': 'hint',
                        'zone_name': '.'}]}
        )


if __name__ == '__main__':
    unittest.main()
