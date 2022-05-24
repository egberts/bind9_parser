#!/usr/bin/env python3
"""
File: test_clauses.py

Description:  Performs unit test on the isc_clauses.py source file.
"""

import unittest
from pyparsing import ParseException, ParseBaseException
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_clauses import \
    optional_clause_stmt_set,\
    optional_clause_stmt_series,\
    mandatory_clause_stmt_set,\
    clause_statements
#   TODO add v9.15.0 new clause_stmt_catalog_zones


class TestClauseALL(unittest.TestCase):
    """ Clause, All """

    def test_isc_clause_clause_stmt_optional_set_passing1(self):
        """ Clause, All; Statements group; optional clause 1; passing """
        test_data = [
            'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };',
        ]
        result = optional_clause_stmt_set.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_clause_clause_stmt_optional_set_dict_passing1(self):
        """ Clause, All; Statements group; optional clause dict 1; passing """
        test_string = 'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };'
        assertParserResultDictTrue(
            optional_clause_stmt_set,
            test_string,
            {'acl': [{'acl_name': 'MY_BASTION_HOSTS',
                      'aml_series': [{'aml': [{'addr': '4.4.4.4'},
                                              {'addr': '3.3.3.3'},
                                              {'addr': '2.2.2.2'},
                                              {'addr': '1.1.1.1'}]}]}]}
        )

    def test_isc_clause_clause_stmt_optional_set_passing(self):
        """ Clause, All; Statements group; passing """
        test_string = 'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };'
        expected_result = { 'acl': [ { 'acl_name': 'MY_BASTION_HOSTS',
             'aml_series': [ { 'aml': [ {'addr': '4.4.4.4'},
                                        {'addr': '3.3.3.3'},
                                        {'addr': '2.2.2.2'},
                                        {'addr': '1.1.1.1'}]}]}]}
        assertParserResultDictTrue(optional_clause_stmt_set, test_string, expected_result)


    def test_isc_clause_stmt_multiplezone_passing(self):
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
        expected_result = { 'zones': [ { 'file': '"root.servers"',
               'type': 'hint',
               'zone_name': '"."'},
             { 'allow_transfer': { 'aml': [ { 'addr': '192.168.23.1'},
                                            { 'addr': '192.168.23.2'}]},
               'class': 'in',
               'file': '"master/master.example.com"',
               'type': 'master',
               'zone_name': '"example.com"'},
             { 'allow_update': {'aml': [{'addr': 'none'}]},
               'class': 'in',
               'file': '"master.localhost"',
               'type': 'master',
               'zone_name': '"localhost"'},
             { 'allow_update': {'aml': [{'addr': 'none'}]},
               'class': 'in',
               'file': '"localhost.rev"',
               'type': 'master',
               'zone_name': '"0.0.127.in-addr.arpa"'},
             { 'class': 'in',
               'file': '"192.168.0.rev"',
               'type': 'master',
               'zone_name': '"0.168.192.IN-ADDR.ARPA"'}]}
        assertParserResultDictTrue(
            optional_clause_stmt_series,
            test_string,
            expected_result
        )

    def test_isc_clause_optional_clause_stmt_series_passing(self):
        """ Clause, All; All Statements group; passing """
        assertParserResultDictTrue(
            optional_clause_stmt_series,
            'acl MY_BASTION_HOSTS { 4.4.4.4; 3.3.3.3; 2.2.2.2; 1.1.1.1; };' +
            'controls { inet 128.0.0.9 port 8006 allow { 128.0.0.10; 128.0.0.11;} read-only yes; };' +
            'dlz your_IBM_2 { database RSDMS; search no; };' +
            'dyndb "example-ldap" "/usr/lib64/bind/ldap.so" { uri "ldap://ldap.example.com"; base "cn=dns, dc=example,dc=com"; auth_method "none"; };' +
            'key dyndns { algorithm hmac-sha512; secret ABCDEFG; };' +
            'logging { channel salesfolks { file "/tmp/sales.log" size 5M; severity info; print-time no;};'+
            ' channel accounting { file "/tmp/acct.log" size 30M; severity info; print-time no; };' +
            ' channel badguys { file "/tmp/alert" size 255G; severity debug 77; print-time yes;}; };' +
            'managed-keys { www1.www.example.com initial-key 1 1 1 "ASBASDASD"; };' +
            'masters bastion_host_group { bastion_hosts22; hidden_bastion; };' +
            'zone red { file "/var/lib/bind9/public/masters/db.example.com"; };' +
            'server 3.4.5.6 { bogus yes; edns no; edns-udp-size 102; edns-version 2;' +
            ' keys my_key_name_to_private_dns; max-udp-size 32768; notify-source *; notify-source-v6 *;' +
            ' padding 53; provide-ixfr yes; query-source *; query-source address *; query-source-v6 *;' +
            ' request-expire yes; request-ixfr yes; request-nsid yes; send-cookie yes; tcp-keepalive yes; ' +
            ' tcp-only yes; transfer-format one-answer; transfer-source *; transfer-source-v6 *; transfers 36; };' +
            'trusted-keys { abc 1 1 1 "ASBASDASD";};' +
            'zone green { file "/var/lib/bind9/public/masters/db.green.com"; };' +
            'masters dmz_masters port 7553 dscp 5 { yellow_masters key priv_dns_chan_key5; };'
            '',
            {'acl': [{'acl_name': 'MY_BASTION_HOSTS',
                      'aml_series': [{'aml': [{'addr': '4.4.4.4'},
                                              {'addr': '3.3.3.3'},
                                              {'addr': '2.2.2.2'},
                                              {'addr': '1.1.1.1'}]}]}],
             'controls': [{'inet': {'allow': {'aml': [{'addr': '128.0.0.10'},
                                                      {'addr': '128.0.0.11'}]},
                                    'control_server_addr': '128.0.0.9',
                                    'ip_port_w': '8006',
                                    'read-only': 'yes'}}],
             'dlz': [{'db_args': 'RSDMS',
                      'dlz_name': 'your_IBM_2',
                      'search': 'no'}],
             'dyndb': [{'db_name': '"example-ldap"',
                        'driver_parameters': 'uri '
                                             '"ldap://ldap.example.com"; '
                                             'base "cn=dns, '
                                             'dc=example,dc=com"; '
                                             'auth_method "none"; ',
                        'module_filename': '"/usr/lib64/bind/ldap.so"'}],
             'key': [{'algorithm': 'hmac-sha512',
                      'key_id': 'dyndns',
                      'secret': 'ABCDEFG'}],
             'logging': [{'channel': [{'channel_name': 'salesfolks',
                                       'path_name': '"/tmp/sales.log"',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [5, 'M']}]},
                         {'channel': [{'channel_name': 'accounting',
                                       'path_name': '"/tmp/acct.log"',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']}]},
                         {'channel': [{'channel_name': 'badguys',
                                       'path_name': '"/tmp/alert"',
                                       'print_time': 'yes',
                                       'severity': {'debug': [77]},
                                       'size_spec': [255, 'G']}]}],
             'managed_keys': [{'algorithm_id': 1,
                               'flags': 1,
                               'key_secret': '"ASBASDASD"',
                               'protocol_id': 1,
                               'rr_domain': 'www1.www.example.com'}],
             'primaries': [{'dscp_port': 5,
                            'ip_port': '7553',
                            'primary_id': 'dmz_masters',
                            'primary_list': [{'addr': 'yellow_masters',
                                              'key_id': 'priv_dns_chan_key5'}]}],
             'server': [{'addr': '3.4.5.6',
                         'configs': {'bogus': 'yes',
                                     'edns': 'no',
                                     'edns_udp_size': 102,
                                     'edns_version': 2,
                                     'keys': 'my_key_name_to_private_dns',
                                     'max_udp_size': 32768,
                                     'notify_source': {'addr': '*'},
                                     'notify_source_v6': {'addr': '*'},
                                     'padding': 53,
                                     'provide_ixfr': 'yes',
                                     'query_source': {'ip4_addr_w': '*'},
                                     'query_source_v6': {'ip6_addr_w': '*'},
                                     'request_expire': 'yes',
                                     'request_ixfr': 'yes',
                                     'request_nsid': 'yes',
                                     'send_cookie': 'yes',
                                     'tcp_keepalive': 'yes',
                                     'tcp_only': 'yes',
                                     'transfer_format': 'one-answer',
                                     'transfer_source': {'ip4_addr_w': '*'},
                                     'transfer_source_v6': {'ip6_addr_w': '*'},
                                     'transfers': 36}}],
             'trusted_keys': [{'algorithm_id': '1',
                               'domain': 'abc',
                               'key_id': '1',
                               'protocol_type': '1',
                               'pubkey_base64': 'ASBASDASD'}],
             'zones': [{'file': '"/var/lib/bind9/public/masters/db.example.com"',
                        'zone_name': 'red'},
                       {'file': '"/var/lib/bind9/public/masters/db.green.com"',
                        'zone_name': 'green'}]}
        )


if __name__ == '__main__':
    unittest.main()
