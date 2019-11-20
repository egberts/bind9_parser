#!/usr/bin/env python3
"""
File: test_aml

Element: AML

Title: Test Address Match List
"""

import unittest
from isc_utils import assertParserResultDict, acl_name, \
    key_id, key_id_list, key_id_list_series, \
    key_id_keyword_and_name_pair, \
    parse_me
from isc_aml import aml_choices, aml_nesting


class TestAML(unittest.TestCase):
    """ Element AML; Address Match List (AML) """

    def test_acl_names_passing(self):
        """ Type ACL Name; passing """
        assertParserResultDict(acl_name, 'example', {'acl_name': 'example'}, True)
        assertParserResultDict(acl_name, '1.1.1.1', {'acl_name': '1.1.1.1'},
                               True)  # Not valid, but an internal correct logic
        assertParserResultDict(acl_name, 'example.com', {'acl_name': 'example.com'}, True)
        assertParserResultDict(acl_name, 'example[com]', {'acl_name': 'example[com]'}, True)
        assertParserResultDict(acl_name, 'example<com>', {'acl_name': 'example<com>'}, True)
        assertParserResultDict(acl_name, 'example&com', {'acl_name': 'example&com'}, True)

    def test_acl_names_failing(self):
        """ Type ACL Name; failing """
        assertParserResultDict(acl_name, 'example.com!', {}, False)
        assertParserResultDict(acl_name, 'ex;mple', {},
                               False)  # obviously cannot use semicolon in acl_name/master_id/aml
        assertParserResultDict(acl_name, 'subdir/example', {}, False)
        assertParserResultDict(acl_name, 'ex#mple', {}, False)  # obviously cannot use hash in acl_name/master_id/aml

    def test_isc_aml_key_id_passing(self):
        """ Element AML; Type key_id; passing """
        assertParserResultDict(key_id, 'myKeyID', {'key_id': 'myKeyID'}, True)
        assertParserResultDict(key_id, 'my_key_id', {'key_id': 'my_key_id'}, True)

    def test_isc_aml_key_id_failing(self):
        """ Element AML; Type key_id; failing """
        assertParserResultDict(key_id, 'myKey#ID', {}, False)
        assertParserResultDict(key_id, 'my/key_id', {}, False)

    def test_isc_aml_key_id_list_passing(self):
        """ Element AML; Type key_id_list; passing """
        assertParserResultDict(key_id_list('key_id'), 'myKey;', {'key_id': ['myKey']}, True)

    def test_isc_aml_key_id_list_series_passing(self):
        """ Element AML; Type key_id_list_series; passing """
        assertParserResultDict(key_id_list_series('key_ids'), 'myKey; yourKey; ourKey;',
                               {'key_ids': ['myKey', 'yourKey', 'ourKey']}, True)

    def test_isc_aml_key_id_keyword_and_name_element_passing(self):
        """ Element AML; Type key_id; passing"""
        assertParserResultDict(key_id_keyword_and_name_pair, 'key myKey2', {'key_id': 'myKey2'}, True)

    def test_isc_aml_key_id_keyword_and_name_element_failing(self):
        """ Element AML; Type key_id; passing"""
        assertParserResultDict(key_id_keyword_and_name_pair, 'key myKey3', {'key_id_WRONG': 'myKey3'}, False)

    def test_aml_choices_passing(self):
        assertParserResultDict(aml_choices, 'any', {'addr': 'any'}, True)
        assertParserResultDict(aml_choices, 'none', {'addr': 'none'}, True)
        assertParserResultDict(aml_choices, 'localhost', {'addr': 'localhost'}, True)
        assertParserResultDict(aml_choices, 'localnets', {'addr': 'localnets'}, True)
        assertParserResultDict(aml_choices, '1.1.1.1', {'addr': '1.1.1.1'}, True)
        assertParserResultDict(aml_choices, '2.2.2.2/2', {'addr': '2.2.2.2/2'}, True)
        assertParserResultDict(aml_choices, 'fe03::3', {'addr': 'fe03::3'}, True)
        assertParserResultDict(aml_choices, 'master_nameservers_acl',
                               {'acl_name': 'master_nameservers_acl'}, True)
        assertParserResultDict(aml_choices, 'example', {'acl_name': 'example'}, True)
        assertParserResultDict(aml_choices, 'key MyKeyId', {'key_id': ['MyKeyId']}, True)
        test_datas = [
            ['key myKeyId', {'key_id': ['myKeyId']}],
            ['127.0.0.1', {'addr': '127.0.0.1'}],
            ['localnets', {'addr': 'localnets'}],
            ['any', {'addr': 'any'}],
            ['none', {'addr': 'none'}],
            ['localhost', {'addr': 'localhost'}],
            ['10.0.0.1/8', {'addr': '10.0.0.1/8'}],
            ['example.com', {'acl_name': 'example.com'}]
            # FQDN-style are valid master name, but treated lik a hostname
        ]
        for this_test_data, this_expected_result in test_datas:
            assertParserResultDict(aml_choices, this_test_data, this_expected_result, True)

    def test_aml_choices_failing(self):
        """ Element AML; Choices AML; failing """
        assertParserResultDict(aml_choices, 'master/nameservers_acl', {}, False)
        assertParserResultDict(aml_choices, 'master_nameservers#acl', {}, False)
        assertParserResultDict(aml_choices, 'master;nameservers_acl', {}, False)

    def test_isc_aml_ip4s_prefix_passing(self):
        """ Element AML; Type ip4s_prefix; passing"""
        assertParserResultDict(aml_choices,
                                '10.10.10.10/10',
                               {'addr': '10.10.10.10/10'}
                               , True)

    def test_isc_aml_ip4s_prefix_failing(self):
        """ Element AML; Type ip4s_prefix; failing"""
        assertParserResultDict(aml_choices, '10.10.10.10/1000', {'addr': ['10.10.10.10/1000']}, False)

    def test_isc_aml_aml_nesting_failing(self):
        """Purposely failing Address Match List (AML) name"""
        test_data = """ {
            acl_mast!er_nameservers;
            1.1,1.1;
            acl_nameX&&&
            { &^%$#; }; }; """
        expected_result = {}
        assertParserResultDict(aml_nesting, test_data, expected_result, False)

        assertParserResultDict(aml_nesting, '{ 5.5.5.5/55; }', {'aml': [{'5.5.5.5/55'}]}, False)
        assertParserResultDict(aml_nesting, '{ 6.6.6.6/0;}', {'6.6.6.6/0'}, False)  # w/o 'aml':
        assertParserResultDict(aml_nesting, '7.7.7', {}, False)
        assertParserResultDict(aml_nesting, '{ 8.8.8.8 };', {}, False)

    def test_isc_aml_aml_nesting_passing(self):
        """ Clause ACL; Element AML spacing; passing """

        test_data = [
            '{ localhost; any; none; };',
            '{ localnets; localhost; none;};',
            '{ !localhost; };',
            '{any;};',
            '{none;};',
            '{localhost;};',
            '{localnets;};',
            '{ none; };',
            '{ localhost; };',
            '{ localnets; };',
            '{ 11.11.11.11; };'
        ]
        result = aml_nesting.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_aml_aml_nesting_part2_failing(self):
        """ Clause ACL; Element AML spacing; failing """

        test_data = ['{ oops };']
        result = aml_nesting.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])
        test_data = [
            """        {
               key DDNS_UPDATER;
               };
   """
        ]
        result = aml_nesting.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

        test_data = """{
             localhost; 
             127.0.0.1; 
             10.0.0.1/8; 
             { 
                 master_nameservers; 
                 slave_bastion_host;
             }; 
             {
                 any;
                 none;
                 localnets;
             };
         };"""
        #  Must be in same ordering as expected result
        expected_result = {
            'aml': [
                {'addr': 'localhost'},
                {'addr': '127.0.0.1'},
                {'addr': '10.0.0.1/8'},
                {'aml': [
                    {'acl_name_WRONG': 'master_nameservers'},
                    {'acl_name': 'slave_bastion_host'}
                ]},
                {'aml': [
                    {'addr': 'any'},
                    {'addr': 'none'},
                    {'addr': 'localnets'}
                ]}
            ]}
        assertParserResultDict(aml_nesting, test_data, expected_result, False)

    def test_aml_choices_nested_passing(self):
        """ Clause ACL; List AML Choices; passing """
        assertParserResultDict(aml_choices, 'any', {'addr': 'any'}, True)
        assertParserResultDict(aml_choices, 'none', {'addr': 'none'}, True)
        assertParserResultDict(aml_choices, 'localhost', {'addr': 'localhost'}, True)
        assertParserResultDict(aml_choices, 'localnets', {'addr': 'localnets'}, True)
        assertParserResultDict(aml_choices, '1.1.1.1', {'addr': '1.1.1.1'}, True)
        assertParserResultDict(aml_choices, '2.2.2.2/2', {'addr': '2.2.2.2/2'}, True)
        assertParserResultDict(aml_choices, 'fe03::3', {'addr': 'fe03::3'}, True)
        assertParserResultDict(aml_choices, 'key my_own_key_id', {'key_id': ['my_own_key_id']}, True)
        assertParserResultDict(aml_choices, 'master_nameservers_acl', {'acl_name': 'master_nameservers_acl'}, True)

    def test_isc_aml_aml_choices_finer(self):
        parse_me(aml_choices, 'key\nA8', True)
        parse_me(aml_choices, 'any', True)
        parse_me(aml_choices, 'none', True)
        #    parse_me(aml_choices, 'oops;', False)   # TODO expand AML (aml_nesting) firstly

        # aml_choices('localhost;' == [['localhost']] because no exclamation '"' mark
        parse_me(aml_choices, 'localhost', True)
        parse_me(aml_choices, 'localnets', True)
        # aml_choices('!localhost;' == [['!', 'localhost']] because no exclamation '"' mark

    def test_aml_choices2_failing(self):
        assertParserResultDict(aml_choices, 'master/nameservers_acl;', {}, False)
        assertParserResultDict(aml_choices, 'master_nameservers#acl;', {}, False)
        assertParserResultDict(aml_choices, 'master;nameservers_acl;', {}, False)

    def test_aml_nesting_forward_passing(self):
        assertParserResultDict(aml_nesting,
                                '{ 1.1.1.1; { 127.0.0.1;}; };',
                               {'aml': [{'addr': '1.1.1.1'}, {'aml': [{'addr': '127.0.0.1'}]}]},
                               True)
        assertParserResultDict(aml_nesting,
                                '{ { 8.8.8.8; }; };',
                               {'aml': [{'aml': [{'addr': '8.8.8.8'}]}]},
                               True)
        assertParserResultDict(aml_nesting,
                                '{ { { 9.9.9.9; }; }; };',
                               {'aml': [{'aml': [{'aml': [{'addr': '9.9.9.9'}]}]}]},
                               True)

    def test_aml_nesting_forward_exclamation_passing(self):
        assertParserResultDict(aml_nesting,
                                '{ ! { 1.1.1.1; { 127.0.0.1;}; }; };',
                               {
                                    'aml': [
                                        {
                                            'aml': [
                                                {'addr': '1.1.1.1'},
                                                {'aml': [
                                                    {'addr': '127.0.0.1'}
                                                ]
                                                }
                                            ],
                                            'not': '!'
                                        }
                                    ]
                                },
                               True)
        assertParserResultDict(aml_nesting,
                                '{ ! 11.11.11.11; { 192.168.1.1;}; };',
                               {
                                    'aml': [
                                        {'addr': '11.11.11.11', 'not': '!'},
                                        {'aml': [{'addr': '192.168.1.1'}]}
                                    ]
                                },
                               True)
        assertParserResultDict(aml_nesting,
                                '{ 3.3.3.3; ! { 127.0.0.1;}; };',
                               {
                                    'aml': [
                                        {'addr': '3.3.3.3'},
                                        {'aml': [{'addr': '127.0.0.1'}], 'not': '!'}
                                    ]},
                               True)
        assertParserResultDict(aml_nesting,
                                '{ 4.4.4.4; { ! 127.0.0.1;}; };',
                               {
                                    'aml': [
                                        {'addr': '4.4.4.4'},
                                        {'aml': [
                                            {
                                                'addr': '127.0.0.1',
                                                'not': '!'
                                            }
                                        ]}
                                    ]},
                               True)
        assertParserResultDict(aml_nesting,
                                '{ 5.5.5.5; { 127.0.0.1;}; };',
                               {'aml': [
                                    {'addr': '5.5.5.5'},
                                    {'aml': [
                                        {'addr': '127.0.0.1'}]}]},
                               True)
        assertParserResultDict(aml_nesting,
                                '{ { 6.6.6.6; }; };',
                               {'aml': [
                                    {'aml': [
                                        {'addr': '6.6.6.6'}]}]},
                               True)
        assertParserResultDict(aml_nesting,
                                '{ { { 7.7.7.7; }; }; };',
                               {'aml': [
                                    {'aml': [
                                        {'aml': [
                                            {'addr': '7.7.7.7'}]}]}]},
                               True)

    def test_aml_nesting_first_addr(self):
        assertParserResultDict(aml_nesting.setDebug(True), '{ key mykey; };', {'aml': [{'key_id': ['mykey']}]}, True)

    def test_aml_nesting_first_exclamation(self):
        assertParserResultDict(aml_nesting.setDebug(True), '{ ! key mykey; };',
                               {'aml': [{'key_id': ['mykey'], 'not': '!'}]}, True)

    def test_aml_nesting_first_addr_series(self):
        test_data = """{ localhost; any; none; };"""
        expected_result = {'aml': [{'addr': 'localhost'}, {'addr': 'any'}, {'addr': 'none'}]}
        assertParserResultDict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_nest(self):
        test_data = """{ localhost; }; """
        expected_result = {'aml': [{'addr': 'localhost'}]}
        assertParserResultDict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_two_nests(self):
        test_data = """{ { localhost; }; }; """
        expected_result = {'aml': [{'aml': [{'addr': 'localhost'}]}]}
        assertParserResultDict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_combo(self):
        test_data = """ { localhost; { none; }; };"""
        expected_result = {'aml': [{'addr': 'localhost'}, {'aml': [{'addr': 'none'}]}]}
        assertParserResultDict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_deep_combo(self):
        test_data = """{ { none; }; localhost; { none; { any; }; }; };"""
        expected_result = {'aml': [{'aml': [{'addr': 'none'}]},
                                   {'addr': 'localhost'},
                                   {'aml': [{'addr': 'none'}, {'aml': [{'addr': 'any'}]}]}]}
        assertParserResultDict(aml_nesting, test_data, expected_result, True)

    # test_aml_nesting_flat is not a valid ISC syntax but an interim syntax checker
    def test_aml_nesting_flat(self):
        test_data = """{ localhost; };"""
        expected_result = {'aml': [{'addr': 'localhost'}]}
        assertParserResultDict(aml_nesting, test_data, expected_result, True)

    def test_isc_aml_aml_nesting_passing(self):
        """Address Match List (AML) name"""
        test_data = [
            '{ 1.1.1.1; };',
            '{ 2.2.2.2/2; };',
            '{ 333::1; };',
            '{ any; };',
            '{ none; };',
            '{ localhost; };',
            '{ localnets; };',
            '{ 4.4.4.4; ma1ster_nameservers; };',
            '{ 4.4.4.4; master_nameservers; };',
            '{ 14.14.14.14; master_nameservers; 15.15.15.15/15; };',
            '{ 5.5.5.5; fe02::1; };',
            '{ fe02::1; 6.6.6.6; };',
            '{ 7.7.7.7; fe03::1; slave_nameservers; };',
            '{ fe01::1; master_nameservers; };',
            '{ master_nameservers; };',
            '{ "rndc-remote5" ; };'
        ]
        aml_nesting.runTests(test_data, failureTests=True)

    def test_aml_aml_nesting_failing(self):
        assertParserResultDict(aml_nesting, '{ 23.23.23.23};', {}, False)  # missing inside semicolon
        assertParserResultDict(aml_nesting, '{ 23.23.23.23;}', {}, False)  # missing outside semicolon


if __name__ == '__main__':
    unittest.main()
