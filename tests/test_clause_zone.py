#!/usr/bin/env python3.7
"""
File: test_zone.py

Clause: zone

Title: Statements Used Only By zone Clause.

Description: Provides zone-related grammar in PyParsing engine
             for ISC-configuration style
"""
import unittest
from pyparsing import cppStyleComment, pythonStyleComment
from isc_utils import assertParserResultDictFalse, assertParserResultDictTrue
from isc_clause_zone import \
    zone_all_stmts_set,\
    zone_all_stmts_series,\
    clause_stmt_zone_standalone,\
    clause_stmt_zone_series


class TestClauseZone(unittest.TestCase):
    """ Clause zone """

    def test_isc_clause_zone__clause_stmt_zone_standalone_passing(self):
        """ Clause zone; Statement zone; passing mode """
        test_data = [
            'zone black { auto-dnssec maintain; };',
            'zone red { allow-update { any; }; };',
            'zone white { update-policy {grant EXAMPLE.COM ms-self EXAMPLE.COM AAAAA;}; };'
        ]
        result = clause_stmt_zone_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_zone__clause_stmt_zone_standalone_dict_passing(self):
        assertParserResultDictTrue(
            clause_stmt_zone_standalone,
            'zone red { auto-dnssec maintain; };',
            {
                'zone': {
                    'auto_dnssec': 'maintain',
                    'zone_name': 'red',
                }
            }
        )

    def test_isc_clause_zone__clause_zone_standalone_passing(self):
        test_data = [""" zone "home" IN { type master; file "/var/lib/bind/internal/master/db.home"; allow-update { none; }; };"""]
        test_clause_stmt_zone = clause_stmt_zone_standalone.copy()
        test_clause_stmt_zone = test_clause_stmt_zone.setWhitespaceChars(' \t')
        test_clause_stmt_zone = test_clause_stmt_zone.ignore(pythonStyleComment)
        test_clause_stmt_zone = test_clause_stmt_zone.ignore(cppStyleComment)
#        test_clause_stmt_zone.ignore(pythonStyleComment)
#        test_clause_stmt_zone.ignore(cppStyleComment)
        result = clause_stmt_zone_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assertParserResultDictTrue(
            clause_stmt_zone_standalone,
            'zone "home" IN { type master; file "/var/lib/bind/internal/master/db.home"; allow-update { none; }; };',
            {
                'zone': {
                    'allow_update': {
                        'aml': [
                            {'addr': 'none'}
                        ]
                    },
                   'file': '"/var/lib/bind/internal/master/db.home"',
                   'type': 'master',
                   'zone_name': '"home"'
                }
            }
        )

    def test_isc_clause_stmt_zone_series_passing(self):
        test_data = """
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
    # zone_all_statements_series.
        assertParserResultDictTrue(
            clause_stmt_zone_series,
            test_data,
            {'zones': [{'zone': {'allow_update': {'aml': [{'addr': 'none'}]},
                                 'file': '"/var/lib/bind/internal/master/db.home"',
                                 'type': 'master',
                                 'zone_name': '"home"'}},
                       {'zone': {'allow_update': {'aml': [{'key_id': ['DDNS_UPDATER']}]},
                                 'file': '"/var/lib/bind/internal/master/db.ip4.1.168.192"',
                                 'fowarders': [[]],
                                 'notify': 'no',
                                 'type': 'master',
                                 'zone_name': '"1.168.192.in-addr.arpa"'}},
                       {'zone': {'allow_update': {'aml': [{'addr': 'none'}]},
                                 'file': '"/var/lib/bind/internal/master/db.localhost"',
                                 'fowarders': [[]],
                                 'notify': 'no',
                                 'type': 'master',
                                 'zone_name': '"localhost"'}},
                       {'zone': {'allow_update': {'aml': [{'addr': 'none'}]},
                                 'file': '"/var/lib/bind/internal/master/db.ip4.127"',
                                 'fowarders': [[]],
                                 'notify': 'no',
                                 'type': 'master',
                                 'zone_name': '"0.0.127.in-addr.arpa"'}},
                       {'zone': {'delegation-only': 'yes',
                                 'file': '"/var/lib/bind/internal/master/db.cache.home"',
                                 'type': 'hint',
                                 'zone_name': '"."'}}]}
        )

    def test_isc_clause_stmt_zone_series_multiplezone_passing(self):
        """ Clause, All; Zone Statements group; passing """
        test_string = """
zone "." {
  type hint;
  file "root.servers";
};
zone "example.com" in{
  type master;
  file "master/master.example.com";
  allow-transfer {192.168.23.1;192.168.23.2;};
};
zone "localhost" in{
  type master;
  file "master.localhost";
  allow-update{none;};
};
zone "0.0.127.in-addr.arpa" in{
  type master;
  file "localhost.rev";
  allow-update{none;};
};
zone "0.168.192.IN-ADDR.ARPA" in{
  type master;
  file "192.168.0.rev";
};"""
        expected_result = { 'zones': [ { 'zone': { 'file': '"root.servers"',
                         'type': 'hint',
                         'zone_name': '"."'}},
             { 'zone': { 'allow_transfer': { 'aml': [ { 'addr': '192.168.23.1'},
                                                      { 'addr': '192.168.23.2'}]},
                         'file': '"master/master.example.com"',
                         'type': 'master',
                         'zone_name': '"example.com"'}},
             { 'zone': { 'allow_update': { 'aml': [ { 'addr': 'none'}]},
                         'file': '"master.localhost"',
                         'type': 'master',
                         'zone_name': '"localhost"'}},
             { 'zone': { 'allow_update': { 'aml': [ { 'addr': 'none'}]},
                         'file': '"localhost.rev"',
                         'type': 'master',
                         'zone_name': '"0.0.127.in-addr.arpa"'}},
             { 'zone': { 'file': '"192.168.0.rev"',
                         'type': 'master',
                         'zone_name': '"0.168.192.IN-ADDR.ARPA"'}}]}
        assertParserResultDictTrue(
            clause_stmt_zone_series,
            test_string,
            expected_result
        )


if __name__ == '__main__':
    unittest.main()
