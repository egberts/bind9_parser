#!/usr/bin/env python3
"""
File: test_clause_controls.py

Description:  Performs unit test on the isc_clause_controls.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDict
from bind9_parser.isc_clause_controls import controls_inet_addr_and_port, controls_inet_allow_element,\
    controls_inet_read_only_element,\
    controls_keys_element, controls_inet_set, clause_stmt_control_series,\
    controls_unix_set


class TestClauseControls(unittest.TestCase):
    """ Clause controls """

    def test_isc_controls_controls_inet_addr_and_port_passing(self):
        """ Clause controls; inet address; passing mode """
        test_data = '127.0.0.1'
        expected_result = {'control_server_addr': '127.0.0.1'}
        assertParserResultDict(controls_inet_addr_and_port, test_data, expected_result, True)
        # assertParserResultDict(acl_name, test_data, expected_result, True)

    def test_isc_controls_addr_passing(self):
        """ Clause controls; Element IP address; passing mode"""
        test_data = [
            '127.0.0.1',
            'ffe1::1',
            '127.0.0.2 port 954',
            'ffe1::1 port 955',
            '*',
        ]
        controls_inet_addr_and_port.runTests(test_data, failureTests=False)

    def test_isc_controls_allow_passing(self):
        """ Clause controls; Element inet allow; passing mode """
        test_data = 'allow { 127.0.0.1; }'
        expected_result = {
            'allow': {  # noticed no '[', because there is exactly ONE 'allow'
                'aml': [
                    {'addr': '127.0.0.1'}
                ]
            }
        }
        assertParserResultDict(controls_inet_allow_element, test_data, expected_result, True)
        test_data = 'allow { }'
        expected_result = {
            'allow': [
            ]
        }
        assertParserResultDict(controls_inet_allow_element, test_data, expected_result, True)

    def test_isc_controls_inet_allow_failing(self):
        """ Clause controls; Element inet allow; failing mode """
        test_data = [
            'deny { 127.0.0.2;}',
            'deny { }',
        ]
        controls_inet_allow_element.runTests(test_data, failureTests=False)

    def test_isc_controls_key_passing(self):
        """ Clause controls; Element key; passing mode """
        test_data = 'keys { rndc-key; }'
        expected_result = {'keys': [{'key_id': 'rndc-key'}]}
        assertParserResultDict(controls_keys_element, test_data, expected_result, True)
        test_data = 'keys { \'quoted-key_id\'; }'
        expected_result = {'keys': [{'key_id': '\'quoted-key_id\''}]}
        assertParserResultDict(controls_keys_element, test_data, expected_result, True)
        test_data = 'keys { "quoted-key_id"; }'
        expected_result = {'keys': [{'key_id': '\"quoted-key_id\"'}]}
        assertParserResultDict(controls_keys_element, test_data, expected_result, True)
        test_data = 'keys { unquoted-key_id; }'
        expected_result = {'keys': [{'key_id': 'unquoted-key_id'}]}
        assertParserResultDict(controls_keys_element, test_data, expected_result, True)
        test_data = 'keys { rndc-key; second_key; third_key;}'
        expected_result = {'keys': [{'key_id': 'rndc-key'}, {'key_id': 'second_key'}, {'key_id': 'third_key'}]}
        assertParserResultDict(controls_keys_element, test_data, expected_result, True)

    def test_isc_clause_controls_controls_inet_read_only_element_passing(self):
        """ Clause controls; Element controls_inet_read_only_element; passing """
        test_data = 'read-only true'
        expected_result = {'read-only': 'True'}
        assertParserResultDict(controls_inet_read_only_element, test_data, expected_result, True)

    def test_isc_clause_controls_controls_inet_set_passing(self):
        """ Clause controls; Element controls_inet_set; passing """
        test_data = 'inet * allow { };'
        expected_result = {'inet': {'control_server_addr': '*', 'allow': []}}
        assertParserResultDict(controls_inet_set, test_data, expected_result, True)
        test_data = 'inet 8.8.8.8 allow { any; };'
        expected_result = {
            'inet':
                {
                    'control_server_addr': '8.8.8.8',
                    'allow':
                        {'aml': [
                            {'addr': 'any'}]}}}
        assertParserResultDict(controls_inet_set, test_data, expected_result, True)

    def test_isc_clause_controls_controls_inet_set_failing(self):
        """ Clause controls; Element controls_inet_set; passing """
        test_data = 'inet localhost allow { };'
        expected_result = {'inet': [{'addr': 'localhost', 'allow': []}]}
        assertParserResultDict(controls_inet_set, test_data, expected_result, False)
        test_data = 'inet any allow { };'
        expected_result = {'inet': [{'addr': 'any', 'allow': []}]}
        assertParserResultDict(controls_inet_set, test_data, expected_result, False)

    def test_isc_controls_unix_group_passing(self):
        """ Clause controls; Element inet group; passing mode """
        test_data = 'unix "/tmp/x" perm 0666 owner 101 group 101;'
        expected_result = {
            'unix': {
                'gid': 101,
                'path_name': '"/tmp/x"',
                'perm': 666,
                'uid': 101
            }
        }
        assertParserResultDict(controls_unix_set, test_data, expected_result, True)

    def test_isc_controls_inet_group_passing(self):
        """ Clause controls; Element inet group; passing mode """
        test_data = [
            'inet 127.0.0.1 port 954 allow { 127.0.0.1; } keys { rndc-key; };',
            'inet ffe1::1 port 954 allow { ffe1::1; } keys { private-rndc-key; };',
            'inet * port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
        ]
        controls_inet_set.runTests(test_data, failureTests=True)

    def test_isc_controls_inet_group_failing(self):
        """ Clause controls; Element inet group; passing mode """
        test_data = [
            '* & port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * p0rt 954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port -954 allow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port 954 disallow { 127.0.0.2; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port 954 allow 127.0.0.2; 127.0.0.3; keys { public-rndc-key; };',
            '* * port 954 allow { hostname; 127.0.0.3;} keys { public-rndc-key; };',
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} masterkeys { public-rndc-key; };',
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public&-rndc-key; };',
            '* * port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public&-rndc-key; }',
        ]
        controls_inet_set.runTests(test_data, failureTests=False)

    def test_isc_controls_statement_single_passing(self):
        """ Clause controls; Single statement, passing mode """
        test_data = 'controls { inet 128.0.0.1 allow {}; };'
        expected_result = {
            'controls': [
                {
                    'inet': {
                        'control_server_addr': '128.0.0.1',
                        'allow': []
                    }
                }
            ]
        }
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet 128.0.0.4 port 8004 allow { 128.0.0.5; 128.0.0.6;} keys { public-rndc-key3; }; };'
        expected_result = {
            'controls': [
                {
                    'inet': {
                        'allow': {
                            'aml': [
                                {'addr': '128.0.0.5'},
                                {'addr': '128.0.0.6'}
                            ]
                        },
                        'control_server_addr': '128.0.0.4',
                        'ip_port_w': 8004,
                        'keys': [{'key_id': 'public-rndc-key3'}]
                    }
                }
            ]
        }
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet 128.0.0.2 allow {localhost;}; };'
        expected_result = {'controls': [{'inet': {'allow': {'aml': [{'addr': 'localhost'}]},
                                                  'control_server_addr': '128.0.0.2'}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet * port 8001 allow {} keys { my-key;};};'
        expected_result = {'controls': [{'inet': {'allow': [],
                                                  'control_server_addr': '*',
                                                  'ip_port_w': 8001,
                                                  'keys': [{'key_id': 'my-key'}]}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = "controls { inet * port 8002 allow {'rndc-users';} keys {'rndc-remote';};};"
        expected_result = {'controls': [{'inet': {'allow': {'aml': [{'acl_name': "'rndc-users'"}]},
                                                  'control_server_addr': '*',
                                                  'ip_port_w': 8002,
                                                  'keys': [{'key_id': "'rndc-remote'"}]}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet 128.0.0.3 allow {}; inet * port 8003 allow {} keys { mykey2;};};'
        expected_result = {'controls': [{'inet': {'allow': [],
                                                  'control_server_addr': '128.0.0.3'}},
                                        {'inet': {'allow': [],
                                                  'control_server_addr': '*',
                                                  'ip_port_w': 8003,
                                                  'keys': [{'key_id': 'mykey2'}]}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet 128.0.0.7 port 8005 allow { 128.0.0.8; } keys { rndc-key4; };};'
        expected_result = {'controls': [{'inet': {'allow': {'aml': [{'addr': '128.0.0.8'}]},
                                                  'control_server_addr': '128.0.0.7',
                                                  'ip_port_w': 8005,
                                                  'keys': [{'key_id': 'rndc-key4'}]}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet 128.0.0.9 port 8006 allow { 128.0.0.10; 128.0.0.11;} read-only yes; };'
        expected_result = {'controls': [{'inet': {'allow': {'aml': [{'addr': '128.0.0.10'},
                                                                    {'addr': '128.0.0.11'}]},
                                                  'control_server_addr': '128.0.0.9',
                                                  'ip_port_w': 8006,
                                                  'read-only': 'yes'}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { inet 128.0.0.12 allow {localhost;};'\
                    + ' inet * port 8007 allow {"rndc-users";} keys {"rndc-remote5";};};'
        expected_result = {
            'controls': [
                {
                    'inet': {
                        'allow': {
                            'aml': [{'addr': 'localhost'}]
                        },
                        'control_server_addr': '128.0.0.12'
                    }
                },
                {
                    'inet': {
                        'allow': {
                            'aml': [
                                {'acl_name': '"rndc-users"'}
                            ]
                        },
                        'control_server_addr': '*',
                        'ip_port_w': 8007,
                        'keys': [{'key_id': '"rndc-remote5"'}]}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)
        test_data = 'controls { unix "/tmp/x" perm 0666 owner 101 group 101; };'
        expected_result = {'controls': [{'unix': {'gid': 101,
                                                  'path_name': '"/tmp/x"',
                                                  'perm': 666,
                                                  'uid': 101}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)

    def test_isc_controls_statement_multiple_element_passing(self):
        """ Clause controls; Multiple Element statement, passing mode """
        test_data = 'controls { unix "/tmp/x" perm 0666 owner 101 group 101; inet 128.0.0.12 allow {localhost;}; };'
        expected_result = {'controls': [{'unix': {'gid': 101,
                                                  'path_name': '"/tmp/x"',
                                                  'perm': 666,
                                                  'uid': 101}},
                                        {'inet': {'allow': {'aml': [{'addr': 'localhost'}]},
                                                  'control_server_addr': '128.0.0.12'}}]}
        assertParserResultDict(clause_stmt_control_series, test_data, expected_result, True)

    def test_isc_clause_stmt_controls_failing(self):
        """ Clause controls; Element statement, failing mode """
        test_data = [
            'controls { inet 10.0.0.1 port 954 allow { 127.0.0.2; 127.0.0.3;} keys { public&-rndc-key; }; };',
            'controls { inet 10.0.0.1 port 954 allow { 127.0.0.2; 127.0.0.3;} read-only; };'
            'controls { group 101 owner 101 unix "/tmp/x" perm 0666; };',
            'controls { group 222 owner 222 unix "/tmp/abc" perm 0444; group 303 owner 303 unix "/tmp/y" perm 0555; };',
        ]
        controls_inet_set.runTests(test_data, failureTests=False)

    def test_isc_controls_statement_python_list_passing(self):
        """ Clause controls; Python List, passing mode """
        test_data = """
                    controls { inet * allow { any; }; };
            controls { inet 128.0.0.1 allow { }; };
            controls { inet 128.0.0.2 allow {localhost;}; };
            controls { inet 128.0.0.4 port 8004 allow { 128.0.0.5; 128.0.0.6;} keys { public_rndc_key3; }; };
        """
        expected_result = {'controls': [{'inet': {'allow': {'aml': [{'addr': '128.0.0.5'},
                                                                    {'addr': '128.0.0.6'}]},
                                                  'control_server_addr': '128.0.0.4',
                                                  'ip_port_w': 8004,
                                                  'keys': [{'key_id': 'public_rndc_key3'}]}}]}
        my_csc = clause_stmt_control_series.setWhitespaceChars(' \t\n')
        assertParserResultDict(my_csc, test_data, expected_result, True)

    def test_isc_controls_statement_python_list2_passing(self):
        """ Clause controls; Python List, passing mode """
        test_data = """
controls {
    unix "/tmp/x" perm 0770 owner 222 group 333;
    inet 128.0.0.13 allow {localhost;};
    inet * port 8008 allow {"rndc-users";} keys {"rndc-remote5";};
    unix "/tmp/x" perm 0444 owner 555 group 666;
    };
"""
        expected_result = {'controls': [{'unix': {'gid': 333,
                                                  'path_name': '"/tmp/x"',
                                                  'perm': 770,
                                                  'uid': 222}},
                                        {'inet': {'allow': {'aml': [{'addr': 'localhost'}]},
                                                  'control_server_addr': '128.0.0.13'}},
                                        {'inet': {'allow': {'aml': [{'acl_name': '"rndc-users"'}]},
                                                  'control_server_addr': '*',
                                                  'ip_port_w': 8008,
                                                  'keys': [{'key_id': '"rndc-remote5"'}]}},
                                        {'unix': {'gid': 666,
                                                  'path_name': '"/tmp/x"',
                                                  'perm': 444,
                                                  'uid': 555}}]}
        my_csc = clause_stmt_control_series.setWhitespaceChars(' \t\n')
        assertParserResultDict(my_csc, test_data, expected_result, True)


if __name__ == '__main__':
    unittest.main()
