#!/usr/bin/env python3
"""
File: test_aml

Element: AML

Title: Test Address Match List
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict, acl_name, \
    key_id, key_id_list, key_id_list_series, \
    key_id_keyword_and_name_pair, \
    parse_me
from bind9_parser.isc_aml import aml_choices, aml_nesting


class TestAML(unittest.TestCase):
    """ Element AML; Address Match List (AML) """

    def test_acl_names_passing(self):
        """ Type ACL Name; passing """
        assert_parser_result_dict(acl_name, 'example', {'acl_name': 'example'}, True)
        assert_parser_result_dict(acl_name, '1.1.1.1', {'acl_name': '1.1.1.1'},
                                  True)  # Not valid, but an internal correct logic
        assert_parser_result_dict(acl_name, 'example.com', {'acl_name': 'example.com'}, True)
        assert_parser_result_dict(acl_name, 'example[com]', {'acl_name': 'example[com]'}, True)
        assert_parser_result_dict(acl_name, 'example<com>', {'acl_name': 'example<com>'}, True)
        assert_parser_result_dict(acl_name, 'example&com', {'acl_name': 'example&com'}, True)

    def test_acl_names_failing(self):
        """ Type ACL Name; failing """
        assert_parser_result_dict(acl_name, 'example.com!', {}, False)
        assert_parser_result_dict(acl_name, 'ex;mple', {},
                                  False)  # obviously cannot use semicolon in acl_name/master_id/aml
        assert_parser_result_dict(acl_name, 'subdir/example', {}, False)
        assert_parser_result_dict(acl_name, 'ex#mple', {}, False)  # obviously cannot use hash in acl_name/master_id/aml

    def test_isc_aml_key_id_passing(self):
        """ Element AML; Type key_id; passing """
        assert_parser_result_dict(key_id, 'myKeyID', {'key_id': 'myKeyID'}, True)
        assert_parser_result_dict(key_id, 'my_key_id', {'key_id': 'my_key_id'}, True)

    def test_isc_aml_key_id_failing(self):
        """ Element AML; Type key_id; failing """
        assert_parser_result_dict(key_id, 'myKey#ID', {}, False)
        assert_parser_result_dict(key_id, 'my/key_id', {}, False)

    def test_isc_aml_key_id_list_passing(self):
        """ Element AML; Type key_id_list; passing """
        assert_parser_result_dict(key_id_list('key_id'), 'myKey;', {'key_id': ['myKey']}, True)

    def test_isc_aml_key_id_list_series_passing(self):
        """ Element AML; Type key_id_list_series; passing """
        assert_parser_result_dict(key_id_list_series('key_ids'), 'myKey; yourKey; ourKey;',
                                  {'key_ids': ['myKey', 'yourKey', 'ourKey']}, True)

    def test_isc_aml_key_id_keyword_and_name_element_passing(self):
        """ Element AML; Type key_id; passing"""
        assert_parser_result_dict(key_id_keyword_and_name_pair, 'key myKey2', {'key_id': 'myKey2'}, True)

    def test_isc_aml_key_id_keyword_and_name_element_failing(self):
        """ Element AML; Type key_id; passing"""
        assert_parser_result_dict(key_id_keyword_and_name_pair, 'key myKey3', {'key_id_WRONG': 'myKey3'}, False)

    def test_aml_choices_passing(self):
        assert_parser_result_dict(aml_choices, 'any', {'keyword': 'any'}, True)
        assert_parser_result_dict(aml_choices, 'none', {'keyword': 'none'}, True)
        assert_parser_result_dict(aml_choices, 'localhost', {'keyword': 'localhost'}, True)
        assert_parser_result_dict(aml_choices, 'localnets', {'keyword': 'localnets'}, True)
        assert_parser_result_dict(aml_choices, '1.1.1.1', {'ip4_addr': '1.1.1.1'}, True)
        assert_parser_result_dict(aml_choices, '2.2.2.2/2', {'ip4_addr': '2.2.2.2', 'prefix': '2'}, True)
        assert_parser_result_dict(aml_choices, 'fe03::3', {'ip6_addr': 'fe03::3'}, True)
        assert_parser_result_dict(aml_choices, 'master_nameservers_acl',
                                  {'acl_name': 'master_nameservers_acl'}, True)
        assert_parser_result_dict(aml_choices, 'example', {'acl_name': 'example'}, True)
        assert_parser_result_dict(aml_choices, 'key MyKeyId', {'key_id': ['MyKeyId']}, True)
        test_datas = [
            ['key myKeyId', {'key_id': ['myKeyId']}],
            ['127.0.0.1', {'ip4_addr': '127.0.0.1'}],
            ['localnets', {'keyword': 'localnets'}],
            ['any', {'keyword': 'any'}],
            ['none', {'keyword': 'none'}],
            ['localhost', {'keyword': 'localhost'}],
            ['10.0.0.1/8', {'ip4_addr': '10.0.0.1', 'prefix': '8'}],
            ['example.com', {'acl_name': 'example.com'}]
            # FQDN-style are valid master name, but treated lik a hostname
        ]
        for this_test_data, this_expected_result in test_datas:
            assert_parser_result_dict(aml_choices, this_test_data, this_expected_result, True)

    def test_aml_choices_failing(self):
        """ Element AML; Choices AML; failing """
        assert_parser_result_dict(aml_choices, 'master/nameservers_acl', {}, False)
        assert_parser_result_dict(aml_choices, 'master_nameservers#acl', {}, False)
        assert_parser_result_dict(aml_choices, 'master;nameservers_acl', {}, False)

    def test_isc_aml_ip4s_prefix_passing(self):
        """ Element AML; Type ip4s_prefix; passing"""
        assert_parser_result_dict(
            aml_choices,
            '10.10.10.10/10',
            {'ip4_addr': '10.10.10.10', 'prefix': '10'},
            True)

    def test_isc_aml_ip4s_prefix_failing(self):
        """ Element AML; Type ip4s_prefix; failing"""
        assert_parser_result_dict(aml_choices, '10.10.10.10/1000', {'ip_addr': ['10.10.10.10/1000']}, False)

    def test_isc_aml_aml_nesting_failing(self):
        """Purposely failing Address Match List (AML) name"""
        test_data = """ {
            acl_mast!er_nameservers;
            1.1,1.1;
            acl_nameX&&&
            { &^%$#; }; }; """
        expected_result = {}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, False)

        assert_parser_result_dict(aml_nesting, '{ 5.5.5.5/55; }', {'aml': [{'5.5.5.5/55'}]}, False)
        assert_parser_result_dict(aml_nesting, '{ 6.6.6.6/0;}', {'6.6.6.6/0'}, False)  # w/o 'aml':
        assert_parser_result_dict(aml_nesting, '7.7.7', {}, False)
        assert_parser_result_dict(aml_nesting, '{ 8.8.8.8 };', {}, False)

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
                {'keyword': 'localhost'},
                {'ip_addr': '127.0.0.1'},
                {'ip_addr': '10.0.0.1/8'},
                {'aml': [
                    {'acl_name_WRONG': 'master_nameservers'},
                    {'acl_name': 'slave_bastion_host'}
                ]},
                {'aml': [
                    {'keyword': 'any'},
                    {'keyword': 'none'},
                    {'keyword': 'localnets'}
                ]}
            ]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, False)

    def test_aml_choices_nested_passing(self):
        """ Clause ACL; List AML Choices; passing """
        assert_parser_result_dict(aml_choices, 'any', {'keyword': 'any'}, True)
        assert_parser_result_dict(aml_choices, 'none', {'keyword': 'none'}, True)
        assert_parser_result_dict(aml_choices, 'localhost', {'keyword': 'localhost'}, True)
        assert_parser_result_dict(aml_choices, 'localnets', {'keyword': 'localnets'}, True)
        assert_parser_result_dict(aml_choices, '1.1.1.1', {'ip4_addr': '1.1.1.1'}, True)
        assert_parser_result_dict(aml_choices, '2.2.2.2/2', {'ip4_addr': '2.2.2.2', 'prefix': '2'}, True)
        assert_parser_result_dict(aml_choices, 'fe03::3', {'ip6_addr': 'fe03::3'}, True)
        assert_parser_result_dict(aml_choices, 'key my_own_key_id', {'key_id': ['my_own_key_id']}, True)
        assert_parser_result_dict(aml_choices, 'master_nameservers_acl', {'acl_name': 'master_nameservers_acl'}, True)

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
        assert_parser_result_dict(aml_choices, 'master/nameservers_acl;', {}, False)
        assert_parser_result_dict(aml_choices, 'master_nameservers#acl;', {}, False)
        assert_parser_result_dict(aml_choices, 'master;nameservers_acl;', {}, False)

    def test_aml_nesting_forward_passing(self):
        assert_parser_result_dict(
            aml_nesting,
            '{ 1.1.1.1; { 127.0.0.1;}; };',
            {'aml': [{'ip4_addr': '1.1.1.1'}, {'aml': [{'ip4_addr': '127.0.0.1'}]}]},
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ { 8.8.8.8; }; };',
            {'aml': [{'aml': [{'ip4_addr': '8.8.8.8'}]}]},
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ { { 9.9.9.9; }; }; };',
            {'aml': [{'aml': [{'aml': [{'ip4_addr': '9.9.9.9'}]}]}]},
            True)

    def test_aml_nesting_forward_exclamation_passing(self):
        assert_parser_result_dict(
            aml_nesting,
            '{ ! { 1.1.1.1; { 127.0.0.1;}; }; };',
            {
                'aml': [
                    {
                        'aml': [
                            {'ip4_addr': '1.1.1.1'},
                            {'aml': [
                                {'ip4_addr': '127.0.0.1'}
                            ]
                            }
                        ],
                        'not': '!'
                    }
                ]
            },
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ ! 11.11.11.11; { 192.168.1.1;}; };',
            {
                'aml': [
                    {
                        'ip4_addr': '11.11.11.11', 'not': '!'},
                    {'aml': [{'ip4_addr': '192.168.1.1'}]}
                ]
            },
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ 3.3.3.3; ! { 127.0.0.1;}; };',
            {
                'aml': [
                    {'ip4_addr': '3.3.3.3'},
                    {'aml': [{'ip4_addr': '127.0.0.1'}], 'not': '!'}
                ]},
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ 4.4.4.4; { ! 127.0.0.1;}; };',
            {
                'aml': [
                    {'ip4_addr': '4.4.4.4'},
                    {'aml': [
                        {
                            'ip4_addr': '127.0.0.1',
                            'not': '!'
                        }
                    ]}
                ]},
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ 5.5.5.5; { 127.0.0.1;}; };',
            {
                'aml': [
                    {'ip4_addr': '5.5.5.5'},
                    {'aml': [
                        {'ip4_addr': '127.0.0.1'}]}]},
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ { 6.6.6.6; }; };',
            {'aml': [
                {'aml': [
                    {'ip4_addr': '6.6.6.6'}]}]},
            True)
        assert_parser_result_dict(
            aml_nesting,
            '{ { { 7.7.7.7; }; }; };',
            {
                'aml': [
                    {
                        'aml': [
                            {
                                'aml': [
                                    {'ip4_addr': '7.7.7.7'}]}]}]},
            True)

    def test_aml_nesting_first_addr(self):
        assert_parser_result_dict(aml_nesting.setDebug(True), '{ key mykey; };', {'aml': [{'key_id': ['mykey']}]}, True)

    def test_aml_nesting_first_exclamation(self):
        assert_parser_result_dict(aml_nesting.setDebug(True), '{ ! key mykey; };',
                                  {'aml': [{'key_id': ['mykey'], 'not': '!'}]}, True)

    def test_aml_nesting_first_addr_series(self):
        test_data = """{ localhost; any; none; };"""
        expected_result = {'aml': [{'keyword': 'localhost'}, {'keyword': 'any'}, {'keyword': 'none'}]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_nest(self):
        test_data = """{ localhost; }; """
        expected_result = {'aml': [{'keyword': 'localhost'}]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_two_nests(self):
        test_data = """{ { localhost; }; }; """
        expected_result = {'aml': [{'aml': [{'keyword': 'localhost'}]}]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_combo(self):
        test_data = """ { localhost; { none; }; };"""
        expected_result = {'aml': [{'keyword': 'localhost'}, {'aml': [{'keyword': 'none'}]}]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, True)

    def test_aml_nesting_first_deep_combo(self):
        test_data = """{ { none; }; localhost; { none; { any; }; }; };"""
        expected_result = {'aml': [{'aml': [{'keyword': 'none'}]},
                                   {'keyword': 'localhost'},
                                   {'aml': [{'keyword': 'none'}, {'aml': [{'keyword': 'any'}]}]}]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, True)

    # test_aml_nesting_flat is not a valid ISC syntax but an interim syntax checker
    def test_aml_nesting_flat(self):
        test_data = """{ localhost; };"""
        expected_result = {'aml': [{'keyword': 'localhost'}]}
        assert_parser_result_dict(aml_nesting, test_data, expected_result, True)

    def test_isc_aml_aml_nesting_2_passing(self):
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
        assert_parser_result_dict(aml_nesting, '{ 23.23.23.23};', {}, False)  # missing inside semicolon
        assert_parser_result_dict(aml_nesting, '{ 23.23.23.23;}', {}, False)  # missing outside semicolon


if __name__ == '__main__':
    unittest.main()
