#!/usr/bin/env python3
"""
File: test_clause_dyndb.py

Title: Unit Test Dynamic Database
"""
import unittest
from bind9_parser.isc_utils import assert_parser_result_dict, assert_parser_result_dict_true
from bind9_parser.isc_clause_dyndb import dyndb_database_name, dyndb_dynamic_module_name, \
    dyndb_custom_driver_configuration, clause_stmt_dyndb_series


class TestClauseDynDB(unittest.TestCase):
    """ Clause dyndb; Dynamic Database (dyndb) """

    def test_isc_dyndb_database_name_passing(self):
        """ Clause dyndb: Element Database Name; passing """
        assert_parser_result_dict(dyndb_database_name, 'custom_driver_data', {'db_name': 'custom_driver_data'}, True)

    def test_isc_dyndb_dynamic_module_passing(self):
        """ Clause dyndb; Element Dynamic Module; passing """
        test_data = '"my_driver.so"'
        expected_result = {
            'module_filename': 'my_driver.so'
        }
        assert_parser_result_dict(dyndb_dynamic_module_name, test_data, expected_result, True)
        test_data = "'dir/my_driver.so'"
        expected_result = {
            'module_filename': 'dir/my_driver.so'
        }
        assert_parser_result_dict(dyndb_dynamic_module_name, test_data, expected_result, True)

    def test_isc_dyndb_driver_config_passing(self):
        """ Clause dyndb; Element Driver Configuration; passing """
        test_data = """ {
    uri "ldap://ldap.example.com";
    base "cn=dns, dc=example,dc=com";
    auth_method "none";
    }
"""
        expected_result = {
            'driver_parameters':
                'uri "ldap://ldap.example.com";\n'
                '    base "cn=dns, dc=example,dc=com";\n'
                '    auth_method "none";\n'
                '    '}
        assert_parser_result_dict(dyndb_custom_driver_configuration, test_data, expected_result, True)

    def test_isc_clause_stmt_dyndb_failing(self):
        """ Clause dyndb; Element Dynamic Database; failing """
        test_data = 'dyndb database_name module_name { }'
        expected_result = {}
        assert_parser_result_dict(clause_stmt_dyndb_series, test_data, expected_result, False)

    def test_isc_clause_stmt_dyndb_passing(self):
        """ Clause dyndb; Element Dynamic Database; passing """
        test_data = 'dyndb My_Custom_database_name "My_Custom_module_name" { unspecified-text };'
        expected_result = {
            'dyndb': [
                {
                    'db_name': 'My_Custom_database_name',
                    'driver_parameters': 'unspecified-text ',
                    # Aha, there is a space before the '}' that we must test for
                    'module_filename': '"My_Custom_module_name"'
                }
            ]
        }
        assert_parser_result_dict_true(
            clause_stmt_dyndb_series,
            test_data,
            {'dyndb': [{'db_name': 'My_Custom_database_name',
                        'driver_parameters': 'unspecified-text ',
                        'module_filename': 'My_Custom_module_name'}]}
        )

    def test_isc_clause_stmt_dyndb_multiple_passing(self):
        """ Clause dyndb; Element Dynamic Database; passing """
        test_data = """
dyndb sample "../driver/.libs/sample.so" { ipv4.example.nil. in-addr.arpa. };
dyndb sample2 "../driver/.libs/sample.so" { ipv6.example.nil. 8.b.d.0.1.0.0.2.ip6.arpa. };
dyndb sample "sample.so" { example.nil. arpa. };
dyndb My_Custom_database_name "dir/file" { unspecified-text };
dyndb hyperfast_mariadb "/usr/lib/libmariadb.so" { max_soconn=4 };
dyndb "example-ldap" "/usr/lib64/bind/ldap.so" {
    uri "ldap://ldap.example.com";
    base "cn=dns, dc=example,dc=com";
    auth_method "none";
};
"""
        assert_parser_result_dict(
            clause_stmt_dyndb_series, 
            test_data, 
            { 'dyndb': [ { 'db_name': 'sample',
               'driver_parameters': 'ipv4.example.nil. '
                                    'in-addr.arpa. ',
               'module_filename': '../driver/.libs/sample.so'},
             { 'db_name': 'sample2',
               'driver_parameters': 'ipv6.example.nil. '
                                    '8.b.d.0.1.0.0.2.ip6.arpa. ',
               'module_filename': '../driver/.libs/sample.so'},
             { 'db_name': 'sample',
               'driver_parameters': 'example.nil. arpa. ',
               'module_filename': 'sample.so'},
             { 'db_name': 'My_Custom_database_name',
               'driver_parameters': 'unspecified-text ',
               'module_filename': 'dir/file'},
             { 'db_name': 'hyperfast_mariadb',
               'driver_parameters': 'max_soconn=4 ',
               'module_filename': '/usr/lib/libmariadb.so'},
             { 'db_name': '"example-ldap"',
               'driver_parameters': 'uri '
                                    '"ldap://ldap.example.com";\n'
                                    '    base "cn=dns, '
                                    'dc=example,dc=com";\n'
                                    '    auth_method "none";\n',
               'module_filename': '/usr/lib64/bind/ldap.so'}]}, 
            True)


if __name__ == '__main__':
    unittest.main()
