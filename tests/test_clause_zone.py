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
from bind9_parser.isc_utils import assertParserResultDictFalse, assertParserResultDictTrue
from bind9_parser.isc_clause_zone import \
    zone_all_stmts_set,\
    zone_all_stmts_series,\
    clause_stmt_zone_standalone,\
    clause_stmt_zone_series


class TestClauseZone(unittest.TestCase):
    """ Test Clause Zone """

    """ exercises all OR operators in zone_all_stmts_set
    zone_all_stmts_set = (
         zone_statements_set
         | optzone_statements_set
         | optviewzone_statements_set
         | optviewzoneserver_statements_set
         | viewzone_statements_set
        )"""
    def test_isc_clause_zone__all_stmts_set_file(self):
        """ Clause zone; All Zone statement file from isc_zone.py via zone_statements_set; passing mode """
        test_string = 'file "a.b.type";'
        expected_result = {'file': '"a.b.type"'}
        assertParserResultDictTrue(
            zone_all_stmts_set,
            test_string,
            expected_result
        )

    def test_isc_clause_zone__all_stmts_set_notify_to_soa(self):
        """ Clause zone; All Zone statement 'notify-to-soa' (from isc_optzone.py via 'optzone_statements_set'dd); passing mode """
        test_string = """notify-to-soa yes;"""
        expected_result = {'notify_to_soa': 'yes'}
        assertParserResultDictTrue(
            zone_all_stmts_set,
            test_string,
            expected_result
        )

    def test_isc_clause_zone__all_stmts_set_also_notify(self):
        """ Clause zone; All Zone statement 'also-notify' (from isc_optzoneserver.py via 'optzoneserver_statements_set'dd); passing mode """
        test_string = """also-notify {mymaster; 1.2.3.4;};"""
        expected_result = {'also_notify': [{'master': 'mymaster'}, {'addr': '1.2.3.4'}]}
        assertParserResultDictTrue(
            zone_all_stmts_set,
            test_string,
            expected_result
        )



    def test_isc_clause_zone__clause_stmt_single2(self):
        """ Clause zone; Statement zone; single2; passing mode """
        test_data = [
            'zone black {type forward; forwarders {1.2.3.4;};};',
        ]
        result = clause_stmt_zone_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

        expected_data = [[['black', 'forward', [['1.2.3.4']]]]]

        assertParserResultDictTrue(
            clause_stmt_zone_standalone,
            test_data,
            expected_data
        )


    def test_isc_clause_zone__clause_stmt_zone_standalone_passing(self):
        """ Clause zone; Statement zone; passing mode """
        test_data = [
            'zone black {type forward;forwarders; {1.2.3.4;};};',
            'zone red {type master;file "x";allow-update {any;};};',
            'zone white.com {type master;file "y";allow-query {1.2.3.4;};};'
        ]
        result = clause_stmt_zone_standalone.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_zone__clause_stmt_zone_standalone_dict_passing(self):
        assertParserResultDictTrue(
            clause_stmt_zone_standalone,
            'zone red { auto-dnssec maintain; };',
            {
                'zones': [{
                    'auto_dnssec': 'maintain',
                    'zone_name': 'red',
                    }]
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
                'zones': [{
                    'allow_update': {
                        'aml': [
                            {'addr': 'none'}
                        ]
                    },
                   'file': '"/var/lib/bind/internal/master/db.home"',
                   'type': 'master',
                   'zone_name': '"home"'
                }
              ]
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
            test_data, expected_result
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
        expected_result = { 
                'zones': [
                    { 'file': '"root.servers"',
                      'type': 'hint',
                      'zone_name': '"."'},
                    { 'allow_transfer': { 'aml': [ { 'addr': '192.168.23.1'},
                                                   { 'addr': '192.168.23.2'}]},
                      'file': '"master/master.example.com"',
                      'type': 'master',
                      'zone_name': '"example.com"'},
                    { 'allow_update': { 'aml': [ { 'addr': 'none'}]},
                      'file': '"master.localhost"',
                      'type': 'master',
                      'zone_name': '"localhost"'},
                    { 'allow_update': { 'aml': [ { 'addr': 'none'}]},
                      'file': '"localhost.rev"',
                      'type': 'master',
                      'zone_name': '"0.0.127.in-addr.arpa"'},
                    { 'file': '"192.168.0.rev"',
                      'type': 'master',
                      'zone_name': '"0.168.192.IN-ADDR.ARPA"'}]}
        assertParserResultDictTrue(
            clause_stmt_zone_series,
            test_string,
            expected_result
        )


if __name__ == '__main__':
    unittest.main()
