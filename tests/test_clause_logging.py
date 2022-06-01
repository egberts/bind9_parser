#!/usr/bin/env python3
"""
File: test_clause_logging.py

Clause : logging

Element: logging

Title: Clause logging; Element logging

Description:  Performs unit test on the isc_clause_logging.py source file.

logging {
        category <string> { <string>; ... }; // may occur multiple times
        channel <string> {
                buffered <boolean>;
                file <quoted_string> [ versions ( unlimited | <integer> ) ]
                    [ size <size> ] [ suffix ( increment | timestamp ) ];
                null;
                print-category <boolean>;
                print-severity <boolean>;
                print-time ( iso8601 | iso8601-utc | local | <boolean> );
                severity <log_severity>;
                stderr;
                syslog [ <syslog_facility> ];
        }; // may occur multiple times
};

"""

import unittest
from bind9_parser.isc_utils import assert_parser_result_dict_true, assert_parser_result_dict_false
from bind9_parser.isc_clause_logging import \
    logging_chan_file_path_version_element,\
    logging_chan_file_path_size_element, \
    logging_chan_file_path_element,\
    logging_chan_syslog_facility_name, \
    logging_chan_syslog_element,\
    logging_chan_file_method, \
    logging_chan_syslog_severity_select, \
    logging_chan_syslog_severity_element,\
    logging_chan_print_category_element, \
    logging_chan_print_severity_element,\
    logging_chan_print_time_element, \
    logging_chan_buffered_element, \
    logging_chan_method_option_set,\
    logging_chan_method_option_series, \
    logging_chan_method_element, \
    logging_stmt_channel_set, \
    logging_channel_name_series,\
    logging_category_name, \
    logging_stmt_category_set, \
    logging_stmt_set, \
    logging_stmt_series,\
    clause_stmt_logging_standalone


class TestClauseLogging(unittest.TestCase):
    """ Clause logging """

    # CHANNELS
    # Versions for number of copies of recent files to keep
    def test_isc_logging_chan_file_path_version_element_passing(self):
        """ Clause logging; Element File path version; passing mode """
        test_string = 'versions 0'
        expected_result = {'versions': 0}
        assert_parser_result_dict_true(logging_chan_file_path_version_element,
                                       test_string,
                                       expected_result)
        test_string = 'versions 1'
        expected_result = {'versions': 1}
        assert_parser_result_dict_true(logging_chan_file_path_version_element,
                                       test_string,
                                       expected_result)
        test_string = 'versions 32769'
        expected_result = {'versions': 32769}
        assert_parser_result_dict_true(logging_chan_file_path_version_element,
                                       test_string,
                                       expected_result)
        test_string = 'versions unlimited'
        expected_result = {'versions': 'unlimited'}
        assert_parser_result_dict_true(logging_chan_file_path_version_element,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_file_path_version_element_failing(self):
        """ Clause logging; Element File path version; failing mode """
        test_string = 'version A;'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_path_version_element,
                                        test_string,
                                        expected_result, 'Alpha characters are not valid file versions')
        test_string = 'version limited;'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_path_version_element,
                                        test_string,
                                        expected_result, 'literal "limited" is not a valid value')
        test_string = 'version not-limited'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_path_version_element,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_file_path_size_element_passing(self):
        """ Clause logging; Element File path size; passing mode """
        test_string = 'size 1M'
        expected_result = {'size_spec': [1, 'M']}
        assert_parser_result_dict_true(logging_chan_file_path_size_element,
                                       test_string,
                                       expected_result)
        test_string = 'size 1024'
        expected_result = {'size_spec': [1024]}
        assert_parser_result_dict_true(logging_chan_file_path_size_element,
                                       test_string,
                                       expected_result)
        test_string = 'size 100'
        expected_result = {'size_spec': [100]}
        assert_parser_result_dict_true(logging_chan_file_path_size_element,
                                       test_string,
                                       expected_result)
        test_string = 'size 10G'
        expected_result = {'size_spec': [10, 'G']}
        assert_parser_result_dict_true(logging_chan_file_path_size_element,
                                       test_string,
                                       expected_result)
        test_string = 'size 10g'
        expected_result = {'size_spec': [10, 'g']}
        assert_parser_result_dict_true(logging_chan_file_path_size_element,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_file_path_size_element_failing(self):
        """ Clause logging; Element File path size; failing mode """
        test_string = 'size 15x'
        expected_result = {'size_spec': [15, 'x']}
        assert_parser_result_dict_false(logging_chan_file_path_size_element,
                                        test_string,
                                        expected_result, '"x" is not a valid size legend')
        test_string = 'size 32kilo'
        expected_result = {'size_spec': [32, ' kilo']}
        assert_parser_result_dict_false(logging_chan_file_path_size_element,
                                        test_string,
                                        expected_result, '"kilo" is not a valid size legend')
        test_string = 'size 65mega'
        expected_result = {'size_spec': [65, 'mega']}
        assert_parser_result_dict_false(logging_chan_file_path_size_element,
                                        test_string,
                                        expected_result, '"mega" s not a valid size legend')
        test_string = 'size 128 mega'
        expected_result = {'size_spec': [128, 'mega']}
        assert_parser_result_dict_false(logging_chan_file_path_size_element,
                                        test_string,
                                        expected_result, '"mega" is not a valid size legend')

    def test_isc_logging_chan_file_path_element_passing(self):
        """ Clause logging; Element File path; passing mode """
        test_string = 'file "simple-relative-filename"'
        expected_result = {'path_name': 'simple-relative-filename'}
        assert_parser_result_dict_true(logging_chan_file_path_element,
                                       test_string,
                                       expected_result, 'did not detect missing semicolon')
        test_string = 'file "/tmp/unquoted-key_id"'
        expected_result = {'path_name': '/tmp/unquoted-key_id'}
        assert_parser_result_dict_true(logging_chan_file_path_element,
                                       test_string,
                                       expected_result, 'did not detect missing semicolon')
        test_string = 'file "/tmp/spaced-out key_id"'
        expected_result = {'path_name': '/tmp/spaced-out key_id'}
        assert_parser_result_dict_true(logging_chan_file_path_element,
                                       test_string,
                                       expected_result, 'did not detect missing semicolon')
#        test_string = 'file /tmp/"spaced dir"/spaced-outkey_id'   # TODO: Either get this working or go generic-string
#        expected_result = {'path_name': '/tmp/spaced dir/spaced-outkey_id'}
#        assertParserResultDictTrue(logging_chan_file_path_element,
#                                   test_string,
#                                   expected_result, 'did not detect missing semicolon')
        test_string = "file '/tmp/spaced-out key_id2'"
        expected_result = {'path_name': '/tmp/spaced-out key_id2'}
        assert_parser_result_dict_true(logging_chan_file_path_element,
                                       test_string,
                                       expected_result, 'did not detect missing semicolon')
        test_string = 'file \'/dev/null\''
        expected_result = {'path_name': '/dev/null'}
        assert_parser_result_dict_true(logging_chan_file_path_element,
                                       test_string,
                                       expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_file_path_element_nosemicolon_failing(self):
        """ Clause logging; Element File path; failing mode """

        test_string = 'file "/control_r\rsubdir/unquoted-key_id"'
        expected_result = {'path_name': '/control_r\rsubdir/unquoted-key_id'}
        assert_parser_result_dict_false(
            logging_chan_file_path_element,
            test_string,
            expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_file_path_element_unquoted_failing(self):
        """ Clause logging; Element File path; failing mode """
        test_string = 'file /control_b\bsubdir/unquoted-key_id'
        expected_result = {'path_name': '/control_b\bsubdir/unquoted-key_id'}
        assert_parser_result_dict_false(logging_chan_file_path_element,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')

        test_string = 'file /gappy subdir/unquoted-key_id'
        expected_result = {'path_name': '/gappy subdir/unquoted-key_id'}
        assert_parser_result_dict_false(logging_chan_file_path_element,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_syslog_facility_name_passing(self):
        """ Clause logging: Keyword facility; passing """
        assert_parser_result_dict_true(
            logging_chan_syslog_facility_name,
            'authpriv',
            {'facility': 'authpriv'}
        )

    def test_isc_logging_chan_syslog_facility_element_empty_passing(self):
        """ Clause logging: Element facility, empty; passing """
        assert_parser_result_dict_true(
            logging_chan_syslog_element,
            'syslog',
            {'syslog': []}
        )

    def test_isc_logging_chan_syslog_facility_element_passing(self):
        """ Clause logging: Element facility; passing """
        assert_parser_result_dict_true(
            logging_chan_syslog_element,
            'syslog authpriv',
            {'syslog': {'facility': 'authpriv'}}
        )

    def test_isc_logging_chan_file_method_passing(self):
        """ Clause logging; Element File Method; passing mode """
        test_string = 'file "unquoted-key_id";'
        expected_result = {'path_name': 'unquoted-key_id'}
        assert_parser_result_dict_true(logging_chan_file_method,
                                       test_string,
                                       expected_result)
        test_string = 'syslog ;'
        expected_result = {'syslog': []}
        assert_parser_result_dict_true(logging_chan_file_method,
                                       test_string,
                                       expected_result)
        test_string = 'syslog daemon;'
        expected_result = {'syslog': {'facility': 'daemon'}}
        assert_parser_result_dict_true(logging_chan_file_method,
                                       test_string,
                                       expected_result)
        test_string = 'stderr;'
        expected_result = {'io': 'stderr'}
        assert_parser_result_dict_true(logging_chan_file_method,
                                       test_string,
                                       expected_result)
        test_string = 'null;'
        expected_result = {'io': 'null'}
        assert_parser_result_dict_true(logging_chan_file_method,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_file_method_failing(self):
        """ Clause logging; Element File Method; failing mode """
        test_string = 'stdin;'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_method,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')
        test_string ='stdout;'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_method,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')
        test_string ='zero;'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_method,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')
        test_string ='file nutz;file-with-semicolon.type;'
        expected_result = {}
        assert_parser_result_dict_false(logging_chan_file_method,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')
        test_string = 'syslog warning;'
        expected_result = {'io': 'null'}
        assert_parser_result_dict_false(logging_chan_file_method,
                                        test_string,
                                        expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_severity_select_debug_passing(self):
        """ Clause logging; Type Channel Severity debug; passing """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_select,
            'debug',
            {'debug': 'debug'}
        )

    def test_isc_logging_chan_severity_select_debug2_passing(self):
        """ Clause logging; Type Channel Severity debug2; passing """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_select,
            "debug 2",
            {'debug': {'debug_level': 2}}
        )

    def test_isc_logging_chan_severity_element_debug_passing(self):
        """ Clause logging; Element Channel Severity debug; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity debug;',
            {'severity': {'debug': 'debug'}}
        )

    def test_isc_logging_chan_severity_element_debug1_passing(self):
        """ Clause logging; Element Channel Severity debug 1; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity debug 1;',
            {'severity': {'debug': {'debug_level': 1}}}
        )

    def test_isc_logging_chan_severity_element_critical_passing(self):
        """ Clause logging; Element Channel Severity critical; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity critical;',
            {'severity': ['critical']}
        )

    def test_isc_logging_chan_severity_element_error_passing(self):
        """ Clause logging; Element Channel Severity error; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity error;',
            {'severity': ['error']}
        )

    def test_isc_logging_chan_severity_element_warning_passing(self):
        """ Clause logging; Element Channel Severity warning; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity warning;',
            {'severity': ['warning']}
        )

    def test_isc_logging_chan_severity_element_notice_passing(self):
        """ Clause logging; Element Channel Severity notice; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity notice;',
            {'severity': ['notice']}
        )

    def test_isc_logging_chan_severity_element_info_passing(self):
        """ Clause logging; Element Channel Severity info; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity info;',
            {'severity': ['info']}
        )

    def test_isc_logging_chan_severity_element_warning2_passing(self):
        """ Clause logging; Element Channel Severity warning; passing mode """
        assert_parser_result_dict_true(
            logging_chan_syslog_severity_element,
            'severity warning;',
            {'severity': ['warning']}
        )

    def test_isc_logging_chan_severity_element_failing(self):
        """ Clause logging; Element Channel Severity; failing mode """
        test_data = [
        ]
        test_string = 'severity warn;'
        expected_result = {'severity': ['warn']}
        assert_parser_result_dict_false(logging_chan_syslog_severity_element,
                                        test_string,
                                        expected_result)
        test_string = 'severity debug high;'
        expected_result = {'severity': {'debug': ['high']}}
        assert_parser_result_dict_false(logging_chan_syslog_severity_element,
                                        test_string,
                                        expected_result)
        test_string = 'severity dire_emergency;'
        expected_result = {'severity': ['dire_emergency']}
        assert_parser_result_dict_false(logging_chan_syslog_severity_element,
                                        test_string,
                                        expected_result)
        test_string = 'severity debug on;'
        expected_result = {'severity': {'debug': ['on']}}
        assert_parser_result_dict_false(logging_chan_syslog_severity_element,
                                        test_string,
                                        expected_result)

    def test_isc_logging_chan_print_category_element_passing(self):
        """ Clause logging; Element Channel Print Category; passing mode """
        test_data = [
        ]
        test_string = 'print-category yes;'
        expected_result = {'print_category': 'yes'}
        assert_parser_result_dict_true(logging_chan_print_category_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-category 1;'
        expected_result = {'print_category': '1'}
        assert_parser_result_dict_true(logging_chan_print_category_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-category False;'
        expected_result = {'print_category': 'False'}
        assert_parser_result_dict_true(logging_chan_print_category_element,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_print_category_element_failing(self):
        """ Clause logging; Element Channel Print Category; failing mode """
        test_data = [
        ]
        test_string = 'print_category yes;'  # underscore used instead of an hyphen
        expected_result = {'print_category': 'False'}
        assert_parser_result_dict_false(logging_chan_print_category_element,
                                        test_string,
                                        expected_result)
        test_string = 'print category yes;'  # missing hyphen
        expected_result = {'print_category': 'False'}
        assert_parser_result_dict_false(logging_chan_print_category_element,
                                        test_string,
                                        expected_result)
        test_string = 'print-categories yes'  # plural form used instead of singular
        expected_result = {'print_category': 'False'}
        assert_parser_result_dict_false(logging_chan_print_category_element,
                                        test_string,
                                        expected_result)

    def test_isc_logging_chan_print_severity_element_passing(self):
        """ Clause logging; Element Channel Print Severity; passing mode """
        test_string = 'print-severity no;'
        expected_result = {'print_severity': 'no'}
        assert_parser_result_dict_true(logging_chan_print_severity_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-severity 1;'
        expected_result = {'print_severity': '1'}
        assert_parser_result_dict_true(logging_chan_print_severity_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-severity True;'
        expected_result = {'print_severity': 'True'}
        assert_parser_result_dict_true(logging_chan_print_severity_element,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_print_severity_element_failing(self):
        """ Clause logging; Element Channel Print Severity; failing mode """
        test_string = 'print-severity severe;'
        expected_result = {'print_severity': 'severe'}
        assert_parser_result_dict_false(logging_chan_print_severity_element,
                                        test_string,
                                        expected_result)

    def test_isc_logging_chan_print_time_element_passing(self):
        """ Clause logging; Element Channel Print Time; passing mode """
        test_string = 'print-time yes;'
        expected_result = {'print_time': 'yes'}
        assert_parser_result_dict_true(logging_chan_print_time_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-time 1;'
        expected_result = {'print_time': '1'}
        assert_parser_result_dict_true(logging_chan_print_time_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-time True;'
        expected_result = {'print_time': 'True'}
        assert_parser_result_dict_true(logging_chan_print_time_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-time local;'
        expected_result = {'print_time': 'local'}
        assert_parser_result_dict_true(logging_chan_print_time_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-time iso8601;'
        expected_result = {'print_time': 'iso8601'}
        assert_parser_result_dict_true(logging_chan_print_time_element,
                                       test_string,
                                       expected_result)
        test_string = 'print-time iso8601-utc;'
        expected_result = {'print_time': 'iso8601-utc'}
        assert_parser_result_dict_true(logging_chan_print_time_element,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_print_time_element_failing(self):
        """ Clause logging; Element Channel Print Time; failing mode """
        test_string = 'print-time off;'
        expected_result = {'print_time': 'off'}
        assert_parser_result_dict_false(logging_chan_print_time_element,
                                        test_string,
                                        expected_result)
        test_string = 'print-time zero;'
        expected_result = {'print_time': 'zero'}
        assert_parser_result_dict_false(logging_chan_print_time_element,
                                        test_string,
                                        expected_result)
        test_string = 'print-time none;'
        expected_result = {'print_time': 'none'}
        assert_parser_result_dict_false(logging_chan_print_time_element,
                                        test_string,
                                        expected_result)
        test_string = 'print-time iso8601-est;'
        expected_result = {'print_time': 'iso8601-est'}
        assert_parser_result_dict_false(logging_chan_print_time_element,
                                        test_string,
                                        expected_result)

    def test_isc_logging_chan_buffered_element_passing(self):
        """  Clause logging; Channel buffered element; passing """
        assert_parser_result_dict_true(
            logging_chan_buffered_element,
            'buffered yes;',
            {'buffered': 'yes'}
        )

    def test_isc_logging_chan_method_buffer_element_severity_warning_passing(selfs):
        """  Clause logging; Buffer element; passing mode """
        assert_parser_result_dict_true(
            logging_chan_method_option_set,
            'severity warning;',
            {'severity': ['warning']}
        )

    def test_isc_logging_chan_method_option_set_passing(self):
        """ Clause logging; Set Method; passing mode """
        test_string = 'print-time 1;'
        expected_result = {'print_time': '1'}
        assert_parser_result_dict_true(logging_chan_method_option_set,
                                       test_string,
                                       expected_result)
        test_string = 'buffered 0;'
        expected_result = {'buffered': '0'}
        assert_parser_result_dict_true(logging_chan_method_option_set,
                                       test_string,
                                       expected_result)
        test_string = 'print-severity True;'
        expected_result = {'print_severity': 'True'}
        assert_parser_result_dict_true(logging_chan_method_option_set,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_method_option_series_passing(self):
        """ Clause logging; Series Method; passing mode """
        test_string = 'print-time 1; buffered 0; print-severity True;'
        expected_result = {'print_time': '1', 'buffered': '0', 'print_severity': 'True'}
        assert_parser_result_dict_true(logging_chan_method_option_series,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_method_option_series_failing(self):
        """ Clause logging; Series Method; failing mode """
        test_string = 'print-time 2; buffered -1; print-severity True;'
        expected_result = {'print_time': '1', 'buffered': '0', 'print_severity': 'True'}
        assert_parser_result_dict_false(logging_chan_method_option_series,
                                        test_string,
                                        expected_result)

    def test_isc_logging_chan_method_element_passing(self):
        """ Clause logging; Element Channel Method; passing mode """
        test_string = 'syslog mail;'
        expected_result = {'syslog': {'facility': 'mail'}}
        assert_parser_result_dict_true(logging_chan_method_element,
                                       test_string,
                                       expected_result)
        test_string = 'syslog local0;'
        expected_result = {'syslog': {'facility': 'local0'}}
        assert_parser_result_dict_true(logging_chan_method_element,
                                       test_string,
                                       expected_result)

    def test_isc_logging_chan_method_element_failing(self):
        """ Clause logging; Element Channel Method; failing mode """
        test_string = 'files /tmp/x size 30M; severity ludicrous; print-time yes;}; };'
        expected_result = {'files': 'local0'}
        assert_parser_result_dict_false(logging_chan_method_element,
                                        test_string,
                                        expected_result)
        test_string = 'syslog hacked;'
        expected_result = {'facility': 'hacked'}
        assert_parser_result_dict_false(logging_chan_method_element,
                                        test_string,
                                        expected_result)
        test_string = 'syslog warning;'
        expected_result = {'facility': 'warning'}
        assert_parser_result_dict_false(logging_chan_method_element,
                                        test_string,
                                        expected_result)

    def test_isc_logging_stmt_channel_passing(self):
        """ Clause logging; Statement Channel; passing mode """
        assert_parser_result_dict_true(
            logging_stmt_channel_set,
            'channel bleep { file "/tmp/x" size 38M; severity warning;};',
            {'channels': [{'channel_name': 'bleep',
                           'path_name': '/tmp/x',
                           'severity': ['warning'],
                           'size_spec': [38, 'M']}]}
        )

    def test_isc_logging_stmt_channel2_passing(self):
        assert_parser_result_dict_true(
            logging_stmt_channel_set,
            'channel klaxon { file "/tmp/x" size 38M; };',
            {'channels': [{'channel_name': 'klaxon',
                           'path_name': '/tmp/x',
                           'size_spec': [38, 'M']}]}
        )

    def test_isc_logging_stmt_channel_failing(self):
        """ Clause logging; Statement Channel; failing mode """
        test_string = 'channel bl eep { file "/tmp/x" size 38M; severity warning;};'
        expected_result = {
            'channel': {
                'channel_name': 'bl',
                'channel_name2': 'eep',
                'path_name': '"/tmp/x"',
                'severity': 'warning',
                'size_spec': [38, 'M']}}
        assert_parser_result_dict_false(logging_stmt_channel_set,
                                        test_string,
                                        expected_result)

    def test_isc_logging_stmt_channel_series_passing(self):
        """ Clause logging; Statement Channel series; passing mode """
        assert_parser_result_dict_true(
            logging_stmt_channel_set,
            'channel bl { file "/tmp/x" size 38M; severity warning;};',
            {'channels': [{'channel_name': 'bl',
                           'path_name': '/tmp/x',
                           'severity': ['warning'],
                           'size_spec': [38, 'M']}]}
        )

    #
    # CATEGORIES
    #
    def test_isc_clause_logging_logging_category_name_passing(self):
        """ Clause logging; Statement Category name; passing mode """
        assert_parser_result_dict_true(
            logging_category_name,
            'abcdefg',
            {'name': 'abcdefg'}
        )

    def test_isc_clause_logging_category_stmt_category_passing(self):
        """ Clause logging; Statement Category; passing mode """
        assert_parser_result_dict_true(
            logging_stmt_category_set,
            'category default { default_syslog; default_debug; };',
            {'category_groups': [{'category_group_name': 'default',
                                  'channel_names': ['default_syslog',
                                                    'default_debug']}]}
        )

    def test_isc_clause_logging_logging_stmt_category2_passing(self):
        assert_parser_result_dict_true(
            logging_stmt_category_set,
            'category unmatched { null; };',
            {'category_groups': [{'category_group_name': 'unmatched',
                                  'channel_names': ['null']}]}
        )

    def test_isc_clause_logging_logging_stmt_category_failing(self):
        """ Clause logging; Statement Category; failing mode """
        assert_parser_result_dict_false(
            logging_stmt_category_set,
            'category k l { b; c; d; };',
            {}
        )

    def test_isc_clause_stmt_logging_passing(self):
        """ Clause logging; Statement Logging; passing mode """
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            'logging { channel siren { file "/tmp/x" size 30M; severity info; print-time yes;}; };',
            {'logging': {'channels': [{'channel_name': 'siren',
                                       'path_name': '/tmp/x',
                                       'print_time': 'yes',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']}]}}
        )

    def test_isc_clause_stmt_logging2_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            'logging { channel floodwatch { file "/tmp/x" size 30M; print-time yes; severity info;}; };',
            {'logging': {'channels': [{'channel_name': 'floodwatch',
                                       'path_name': '/tmp/x',
                                       'print_time': 'yes',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']}]}}
        )

    def test_isc_clause_stmt_logging3_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            'logging { channel tv { file "/tmp/x" size 30M; severity info; print-time yes;}; };',
            {'logging': {'channels': [{'channel_name': 'tv',
                                       'path_name': '/tmp/x',
                                       'print_time': 'yes',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']}]}}
        )

    def test_isc_clause_stmt_logging4_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            'logging { channel office_vpn { file "/tmp/x" size 42M; severity critical; print-time no;}; };',
            {'logging': {'channels': [{'channel_name': 'office_vpn',
                                       'path_name': '/tmp/x',
                                       'print_time': 'no',
                                       'severity': ['critical'],
                                       'size_spec': [42, 'M']}]}}
        )

    def test_isc_clause_stmt_logging_multiple_passing(self):
        """ Clause logging; Statement, Multiple; passing mode """
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            'logging { channel salesfolks { file "/tmp/sales.log" size 5M; severity info; print-time no;};'  +
            ' channel accounting { file "/tmp/acct.log" size 30M; severity info; print-time no;};' +
            ' channel badguys { file "/tmp/alert" size 255G; severity debug 77; print-time yes;}; };',
            {'logging': {'channels': [{'channel_name': 'salesfolks',
                                       'path_name': '/tmp/sales.log',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [5, 'M']},
                                      {'channel_name': 'accounting',
                                       'path_name': '/tmp/acct.log',
                                       'print_time': 'no',
                                       'severity': ['info'],
                                       'size_spec': [30, 'M']},
                                      {'channel_name': 'badguys',
                                       'path_name': '/tmp/alert',
                                       'print_time': 'yes',
                                       'severity': {'debug': {'debug_level': 77}},
                                       'size_spec': [255, 'G']}]}}
        )

    def test_isc_logging_clause_stmt_failing(self):
        """ Clause logging; Statement Logging; failing mode """
        test_string = 'logging { channel cb { files "/tmp/x" size 30M; severity info; print-time yes;}; };'
        expected_result = {}
        assert_parser_result_dict_false(clause_stmt_logging_standalone,
                                        test_string,
                                        expected_result)
        test_string = 'logging { channel trucker { file "/tmp/x" size 30M; print__ime yes; severity info;}; };'
        expected_result = {}
        assert_parser_result_dict_false(clause_stmt_logging_standalone,
                                        test_string,
                                        expected_result)

    def test_isc_clause_stmt_logging_issue33_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            """
logging {
channel "general_file" {
file "/var/log/named/general.log" versions 10 size 104857600;
severity dynamic;
print-time yes;
print-severity yes;
print-category yes;
};
category "general" {
"general_file";
"notice-alert_file"; 
};
};""",
            {'logging': {'category_groups': [{'category_group_name': 'general',
                                              'channel_names': ['general_file',
                                                                'notice-alert_file']}],
                         'channels': [{'channel_name': 'general_file',
                                       'path_name': '/var/log/named/general.log',
                                       'print_category': 'yes',
                                       'print_severity': 'yes',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [104857600],
                                       'versions': 10}]}}
        )

    def test_isc_clause_stmt_logging_maximum_passing(self):
        assert_parser_result_dict_true(
            clause_stmt_logging_standalone,
            """
logging {
    channel default_channel {
        file "/var/log/named/public/default.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel general_channel {
        file "/var/log/named/public/general.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel database_channel {
        file "/var/log/named/public/database.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel security_channel {
        file "/var/log/named/public/security.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
    };
    channel config_channel {
        file "/var/log/named/public/config.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel resolver_channel {
        file "/var/log/named/public/resolver.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel xfer-in_channel {
        file "/var/log/named/public/xfer-in.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel xfer-out_channel {
        file "/var/log/named/public/xfer-out.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel notify_channel {
        file "/var/log/named/public/notify.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel client_channel {
        file "/var/log/named/public/client.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel unmatched_channel {
        file "/var/log/named/public/unmatched.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel queries_channel {
        file "/var/log/named/public/queries.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel query-errors_channel {
        file "/var/log/named/public/query-errors.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel network_channel {
        file "/var/log/named/public/network.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel update_channel {
        file "/var/log/named/public/update.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel update-security_channel {
        file "/var/log/named/public/update-security.log" versions 3 size 5m;
        severity info;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel dispatch_channel {
        file "/var/log/named/public/dispatch.log" versions 3 size 5m;
        severity dynamic;
        print-time no;
        print-severity true;
        print-category true;
    };
    channel dnssec_channel {
        file "/var/log/named/public/dnssec.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity no;
        print-category true;
    };
    channel lame-servers_channel {
        file "/var/log/named/public/lame-servers.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel delegation-only_channel {
        file "/var/log/named/public/delegation-only.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category no;
    };
    channel rate-limit_channel {
        file "/var/log/named/public/rate-limit.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };
    channel audit_channel {
        file "/var/log/named/public/audit.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity true;
        print-category true;
    };

    category default { default_channel; general_channel; database_channel; };
    category general { general_channel; };
    category database { database_channel; };
    category security { security_channel; };
    category config { config_channel; };
    category resolver { resolver_channel; };
    category xfer-in { xfer-in_channel; };
    category xfer-out { xfer-out_channel; };
    category notify { notify_channel; };
    category client { client_channel; };
    category unmatched { unmatched_channel; };
    category queries { queries_channel; };
    category query-errors { query-errors_channel; };
    category network { network_channel; };
    category update { update_channel; };
    category update-security { update-security_channel; };
    category dispatch { dispatch_channel; };
    category dnssec { dnssec_channel; };
    category lame-servers { lame-servers_channel; };
    category delegation-only { delegation-only_channel; };
    category rate-limit { rate-limit_channel; };
};
""",
            {'logging': {'category_groups': [{'category_group_name': 'default',
                                              'channel_names': ['default_channel',
                                                                'general_channel',
                                                                'database_channel']},
                                             {'category_group_name': 'general',
                                              'channel_names': ['general_channel']},
                                             {'category_group_name': 'database',
                                              'channel_names': ['database_channel']},
                                             {'category_group_name': 'security',
                                              'channel_names': ['security_channel']},
                                             {'category_group_name': 'config',
                                              'channel_names': ['config_channel']},
                                             {'category_group_name': 'resolver',
                                              'channel_names': ['resolver_channel']},
                                             {'category_group_name': 'xfer-in',
                                              'channel_names': ['xfer-in_channel']},
                                             {'category_group_name': 'xfer-out',
                                              'channel_names': ['xfer-out_channel']},
                                             {'category_group_name': 'notify',
                                              'channel_names': ['notify_channel']},
                                             {'category_group_name': 'client',
                                              'channel_names': ['client_channel']},
                                             {'category_group_name': 'unmatched',
                                              'channel_names': ['unmatched_channel']},
                                             {'category_group_name': 'queries',
                                              'channel_names': ['queries_channel']},
                                             {'category_group_name': 'query-errors',
                                              'channel_names': ['query-errors_channel']},
                                             {'category_group_name': 'network',
                                              'channel_names': ['network_channel']},
                                             {'category_group_name': 'update',
                                              'channel_names': ['update_channel']},
                                             {'category_group_name': 'update-security',
                                              'channel_names': ['update-security_channel']},
                                             {'category_group_name': 'dispatch',
                                              'channel_names': ['dispatch_channel']},
                                             {'category_group_name': 'dnssec',
                                              'channel_names': ['dnssec_channel']},
                                             {'category_group_name': 'lame-servers',
                                              'channel_names': ['lame-servers_channel']},
                                             {'category_group_name': 'delegation-only',
                                              'channel_names': ['delegation-only_channel']},
                                             {'category_group_name': 'rate-limit',
                                              'channel_names': ['rate-limit_channel']}],
                         'channels': [{'channel_name': 'default_channel',
                                       'path_name': '/var/log/named/public/default.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'general_channel',
                                       'path_name': '/var/log/named/public/general.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'database_channel',
                                       'path_name': '/var/log/named/public/database.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'security_channel',
                                       'path_name': '/var/log/named/public/security.log',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'config_channel',
                                       'path_name': '/var/log/named/public/config.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'resolver_channel',
                                       'path_name': '/var/log/named/public/resolver.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'xfer-in_channel',
                                       'path_name': '/var/log/named/public/xfer-in.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'xfer-out_channel',
                                       'path_name': '/var/log/named/public/xfer-out.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'notify_channel',
                                       'path_name': '/var/log/named/public/notify.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'client_channel',
                                       'path_name': '/var/log/named/public/client.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'unmatched_channel',
                                       'path_name': '/var/log/named/public/unmatched.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'queries_channel',
                                       'path_name': '/var/log/named/public/queries.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['info'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'query-errors_channel',
                                       'path_name': '/var/log/named/public/query-errors.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'network_channel',
                                       'path_name': '/var/log/named/public/network.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'update_channel',
                                       'path_name': '/var/log/named/public/update.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'update-security_channel',
                                       'path_name': '/var/log/named/public/update-security.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['info'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'dispatch_channel',
                                       'path_name': '/var/log/named/public/dispatch.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'no',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'dnssec_channel',
                                       'path_name': '/var/log/named/public/dnssec.log',
                                       'print_category': 'True',
                                       'print_severity': 'no',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'lame-servers_channel',
                                       'path_name': '/var/log/named/public/lame-servers.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'delegation-only_channel',
                                       'path_name': '/var/log/named/public/delegation-only.log',
                                       'print_category': 'no',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'rate-limit_channel',
                                       'path_name': '/var/log/named/public/rate-limit.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3},
                                      {'channel_name': 'audit_channel',
                                       'path_name': '/var/log/named/public/audit.log',
                                       'print_category': 'True',
                                       'print_severity': 'True',
                                       'print_time': 'yes',
                                       'severity': ['dynamic'],
                                       'size_spec': [5, 'm'],
                                       'versions': 3}]}}
        )


# TODO: Needs unit test for
#
#       parse_me(logging_chan_syslog_severity_element, 'severity critical;', True)
#       parse_me(logging_chan_syslog_severity_element, 'severity debug 1;', True)


if __name__ == '__main__':
    unittest.main()
