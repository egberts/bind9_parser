#!/usr/bin/env python3
"""
File: test_optviewzoneserver.py

Description:  Performs unit test on the isc_optviewzoneserver.py source file.
"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true
from bind9_parser.isc_optviewzoneserver import \
    optviewzoneserver_also_notify_subgroup_element2, \
    optviewzoneserver_also_notify_subgroup_subelement1, \
    optviewzoneserver_also_notify_subgroup_series, \
    optviewzoneserver_also_notify_group_element_set, \
    optviewzoneserver_stmt_also_notify, \
    optviewzoneserver_stmt_request_expire, \
    optviewzoneserver_statements_set, \
    optviewzoneserver_statements_series


class TestOptionsViewZoneServer(unittest.TestCase):
    """ Clause Options/View/Zone/Server; only under 'options', 'view', 'zone', and 'server' clause """

    def test_isc_optviewzoneserver_stmt_also_notify_subgroup_element_passing(self):
        """ Clause options/view/zone/server; Statement also-notify subgroup element ; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_subgroup_subelement1,
            'key my_keyname',
            {'key_id': 'my_keyname'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_subgroup_element2_passing(self):
        """ Clause options/view/zone/server; Statement also-notify subgroup 2-element ; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_subgroup_subelement1,
            'key my_keyname tls TLSv1.2',
            {'key_id': 'my_keyname', 'tls_algorithm_name': 'TLSv1.2'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_subgroup_element2r_passing(self):
        """ Clause options/view/zone/server; Statement also-notify subgroup 2-element-reverse ; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_subgroup_subelement1,
            'tls TLSv1.0 key my_other_keyname',
            {'key_id': 'my_other_keyname', 'tls_algorithm_name': 'TLSv1.0'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_subgroup_element1o_passing(self):
        """ Clause options/view/zone/server; Statement also-notify subgroup 1-element-other; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_subgroup_subelement1,
            'tls TLSv1.0',
            {'tls_algorithm_name': 'TLSv1.0'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_elems_ip4_passing(self):
        """ Clause options/view/zone/server; Statement also-notify element ipv4; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_subgroup_element2,
            '127.0.0.1',
            {'ip_addr': '127.0.0.1'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_elems_ip6_passing(self):
        """ Clause options/view/zone/server; Statement also-notify element ipv6; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_subgroup_element2,
            'fec2::1 port 333',
            {'ip_addr': 'fec2::1', 'ip_port': '333'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_group_element_passing(self):
        """ Clause options/view/zone/server; Statement also-notify group element; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_also_notify_group_element_set,
            'port 444 dscp 7',
            {'dscp': 7, 'port': '444'}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_subgroup_series_ut_passing(self):
        """ Clause options/view/zone/server; Statement also-notify element series unittest; passing """
        test_string_list = [
            '172.1.1.1 port 543; fec2::1 key my_key_name;',
            '192.168.1.1 port 57 key lockbox5_key; 9.9.9.9 port 123 tls TLSv1.2;',
            'my_primary_name key lockbox5_key; 9.9.9.9 port 123 tls TLSv1.2;',
        ]
        result = optviewzoneserver_also_notify_subgroup_series.runTests(
            test_string_list,
            failureTests=False)
        self.assertTrue(result[0])
        
    def test_isc_optviewzoneserver_stmt_also_notify_group_ut_passing(self):
        """ Clause options/view/zone/server; Statement also-notify group unittest; passing """
        test_string_list = [
            '127.0.0.1;',  # never empty
            '127.0.0.1; 172.16.1.1; 10.0.0.1;',
            '1.1.1.1 port 543;',
            '1.1.1.1 port 57 key lockbox5_key;',
            '1.1.1.1 key lockbox4_key;',
            'fe01::1;',
            'fe01::1 key lockbox8_key;',
            'fe01::1 port 59;',
            'fe01::1 port 59 key lockbox9_key;',
            'primary_or_master_name;',
        ]
        result = optviewzoneserver_also_notify_subgroup_series.runTests(
            test_string_list,
            failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzoneserver_stmt_also_notify_simple_passing(self):
        """ Clause options/view/zone/server; Statement also-notify simple; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_stmt_also_notify,
            'also-notify { 127.0.0.1; };',
            {'also-notify': {'remote': [{'ip_addr': '127.0.0.1'}]}}
        )

    def test_isc_optviewzoneserver_stmt_also_notify_2list_passing(self):
        """ Clause options/view/zone/server; Statement also-notify 2-list; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_stmt_also_notify,
            'also-notify { 127.0.0.1; 172.16.1.1; };',
            {'also-notify': {'remote': [{'ip_addr': '127.0.0.1'},
                                        {'ip_addr': '172.16.1.1'}]}}
            )

    def test_isc_optviewzoneserver_stmt_also_notify_full_passing(self):
        """ Clause options/view/zone/server; Statement also-notify full; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_stmt_also_notify,
            """also-notify port 567 dscp 5 {
    fe01::1 port 59 key lockbox9_key tls TLSv1.3;
    172.16.1.1 port 59 key lockbox9_key tls TLSv1.0;
};""",
            {'also-notify': {'dscp': 5,
                             'port': '567',
                             'remote': [{'ip_addr': 'fe01::1',
                                         'ip_port': '59',
                                         'key_id': 'lockbox9_key',
                                         'tls_algorithm_name': 'TLSv1.3'},
                                        {'ip_addr': '172.16.1.1',
                                         'ip_port': '59',
                                         'key_id': 'lockbox9_key',
                                         'tls_algorithm_name': 'TLSv1.0'}]}}
            )

    def test_isc_optviewzoneserver_stmt_also_notify_passing(self):
        """ Clause options/view/zone/server; Statement also-notify; passing """
        test_string_list = [
            'also-notify { 127.0.0.1; };',  # never empty
            'also-notify port 543 { 127.0.0.1; };',
            'also-notify dscp 10 { 127.0.0.1; };',
            'also-notify port 654 dscp 11 { 127.0.0.1; };',
            'also-notify dscp 11 port 654 { 127.0.0.1; };',
            'also-notify { 127.0.0.1; 172.16.1.1; 10.0.0.1; };',
            'also-notify { 1.1.1.1 port 543; };',
            'also-notify { 1.1.1.1 port 57 key lockbox5_key; };',
            'also-notify { 1.1.1.1 key lockbox4_key; };',
            'also-notify { fe01::1; };',
            'also-notify { fe01::1 key lockbox8_key; };',
            'also-notify { fe01::1 port 59; };',
            'also-notify { fe01::1 port 59 key lockbox9_key; };',
            'also-notify { primary_or_master_name; };',
            'also-notify { primary_name0; };',
            'also-notify port 654 { primary_name1; };',
            'also-notify dscp 3 { primary_name2; };',
            'also-notify port 865 dscp 2 { primary_namer3; };',
        ]
        result = optviewzoneserver_stmt_also_notify.runTests(
            test_string_list,
            failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzoneserver_stmt_also_notify_2_passing(self):
        """ Clause options/view/zone/server; Statement also-notify 2; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_stmt_also_notify,
            """also-notify port 58 dscp 2
{ 
    111.111.111.111 port 5558 key lockbox6_key; 
    fe01::1 key lockbox11_key;
};""",
            {'also-notify': {'dscp': 2,
                             'port': '58',
                             'remote': [{'ip_addr': '111.111.111.111',
                                         'ip_port': '5558',
                                         'key_id': 'lockbox6_key'},
                                        {'ip_addr': 'fe01::1',
                                         'key_id': 'lockbox11_key'}]}}
        )

    def test_isc_optviewzoneserver_stmt_request_expire_passing(self):
        """ Clause options/view/zone/server; Statement request-expire; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_stmt_request_expire,
            'request-expire yes;',
            {'request_expire': 'yes'}
        )

    def test_isc_optviewzoneserver_statements_set_passing(self):
        """ Clause optviewzoneserver; Statement statements_set; passing """
        test_string = [
            'also-notify port 53 { 127.0.0.1; };',
            'also-notify port 53 dscp 1 { 127.0.0.1; };',
            'also-notify dscp 1 port 53 { 127.0.0.1; };',
            'also-notify { masters; };',
            'also-notify { 1.1.1.1; };',
            'also-notify { 1.1.1.1 key lockbox4_key; };',
            'also-notify { 1.1.1.1 port 57; };',
            'also-notify { 1.1.1.1 port 57 key lockbox5_key; };',
            'also-notify { fe01::1; };',
            'also-notify { fe01::1 key lockbox8_key; };',
            'also-notify { fe01::1 port 59; };',
            'also-notify { fe01::1 port 59 key lockbox9_key; };',
            'also-notify { 1.1.1.1 port 58 key lockbox6_key; fe01::1 key lockbox11_key; };',
            'also-notify { primaries; };',
            'also-notify { masters; };',
            'also-notify { 1.1.1.1; };',
            'also-notify { 11.11.11.11 port 11; };',
            'also-notify { 11.11.11.11 key MY_UPDATER; };',
            'also-notify { 11.11.11.11 port 11 key MY_UPDATER; };',
            'also-notify { fe01::1; };',
            'also-notify { fe01::1 key YOUR_UPDATER; };',
            'also-notify { fe01::1 port 12; };',
            'also-notify { fe01::1 port 12 key YOUR_UPDATER; };',
        ]
        result = optviewzoneserver_statements_set.runTests(test_string, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_optviewzoneserver_statements_set_2_passing(self):
        """ Clause optviewzoneserver; Statement statements_set 2; passing """
        assert_parser_result_dict_true(
            optviewzoneserver_statements_set,
            'also-notify { 1.1.1.1 port 58 key lockbox6_key; };',
            {'also-notify': {'remote': [{'ip_addr': '1.1.1.1',
                                         'ip_port': '58',
                                         'key_id': 'lockbox6_key'}]}}
        )

    def test_isc_optviewzoneserver_stmt_statements_set_failing(self):
        """ Clause optviewzoneserver; Statement statements_set; failing """
        test_string = [
            'statements_set "YYYY";',
        ]
        result = optviewzoneserver_statements_set.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_optviewzoneserver_statements_series_passing(self):
        """ Clause optviewzoneserver; Statement optviewzoneserver_statements_series; passing """
        # Only one also-notify allowed per clause section (be that it may, options, view, zone, or server).
        assert_parser_result_dict_true(
            optviewzoneserver_statements_series,
            'also-notify { 1.1.1.1 port 58 key lockbox6_key; };' +
            'also-notify { 2.2.2.2 port 52 key lockbox16_key; };',
            # This is a unique case of just saving the last statement out of 2
            {'also-notify': {'remote': [{'ip_addr': '2.2.2.2',
                                         'ip_port': '52',
                                         'key_id': 'lockbox16_key'}]}}
        )

    def test_isc_optviewzoneserver_stmt_statements_series_failing(self):
        """ Clause optviewzoneserver; Statement statements_series; failing """
        test_string = [
            'statements_series "YYYY";',
        ]
        result = optviewzoneserver_statements_series.runTests(test_string, failureTests=True)
        self.assertTrue(result[0])


if __name__ == '__main__':
    unittest.main()
