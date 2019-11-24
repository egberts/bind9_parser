#!/usr/bin/env python3
"""
File: test_clause_logging.py

Clause : logging

Element: logging

Title: Clause logging; Element logging

Description:  Performs unit test on the isc_clause_logging.py source file.
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue, assertParserResultDictFalse
from bind9_parser.isc_clause_logging import logging_chan_file_path_version_element,\
    logging_chan_file_path_size_element, logging_chan_file_path_element,\
    logging_chan_file_method, logging_chan_syslog_severity_element,\
    logging_chan_syslog_severity_select,\
    logging_chan_print_category_element, logging_chan_print_severity_element,\
    logging_chan_print_time_element, logging_chan_method_option_set,\
    logging_chan_method_option_series, \
    logging_stmt_channel_set, \
    logging_stmt_category_set,\
    logging_chan_method_element,\
    logging_channel_name_series, logging_category_name,\
    logging_stmt_set, logging_stmt_series,\
    clause_stmt_logging_standalone


class TestClauseLogging(unittest.TestCase):
    """ Clause logging """
    def test_isc_logging_chan_file_path_version_element_passing(self):
        """ Clause logging; Element File path version; passing mode """
        test_string = 'versions 0'
        expected_result = {'versions': 0}
        assertParserResultDictTrue(logging_chan_file_path_version_element,
                                   test_string,
                                   expected_result)
        test_string = 'versions 1'
        expected_result = {'versions': 1}
        assertParserResultDictTrue(logging_chan_file_path_version_element,
                                   test_string,
                                   expected_result)
        test_string = 'versions 32769'
        expected_result = {'versions': 32769}
        assertParserResultDictTrue(logging_chan_file_path_version_element,
                                   test_string,
                                   expected_result)
        test_string = 'versions unlimited'
        expected_result = {'versions': 'unlimited'}
        assertParserResultDictTrue(logging_chan_file_path_version_element,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_file_path_version_element_failing(self):
        """ Clause logging; Element File path version; failing mode """
        test_string = 'version A;'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_path_version_element,
                                    test_string,
                                    expected_result, 'Alpha characters are not valid file versions')
        test_string = 'version limited;'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_path_version_element,
                                    test_string,
                                    expected_result, 'literal "limited" is not a valid value')
        test_string = 'version not-limited'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_path_version_element,
                                    test_string,
                                    expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_file_path_size_element_passing(self):
        """ Clause logging; Element File path size; passing mode """
        test_string = 'size 1M'
        expected_result = {'size_spec': [1, 'M']}
        assertParserResultDictTrue(logging_chan_file_path_size_element,
                                   test_string,
                                   expected_result)
        test_string = 'size 1024'
        expected_result = {'size_spec': [1024]}
        assertParserResultDictTrue(logging_chan_file_path_size_element,
                                   test_string,
                                   expected_result)
        test_string = 'size 100'
        expected_result = {'size_spec': [100]}
        assertParserResultDictTrue(logging_chan_file_path_size_element,
                                   test_string,
                                   expected_result)
        test_string = 'size 10G'
        expected_result = {'size_spec': [10, 'G']}
        assertParserResultDictTrue(logging_chan_file_path_size_element,
                                   test_string,
                                   expected_result)
        test_string = 'size 10g'
        expected_result = {'size_spec': [10, 'g']}
        assertParserResultDictTrue(logging_chan_file_path_size_element,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_file_path_size_element_failing(self):
        """ Clause logging; Element File path size; failing mode """
        test_string = 'size 15x'
        expected_result = {'size_spec': [15, 'x']}
        assertParserResultDictFalse(logging_chan_file_path_size_element,
                                    test_string,
                                    expected_result, '"x" is not a valid size legend')
        test_string = 'size 32kilo'
        expected_result = {'size_spec': [32, ' kilo']}
        assertParserResultDictFalse(logging_chan_file_path_size_element,
                                    test_string,
                                    expected_result, '"kilo" is not a valid size legend')
        test_string = 'size 65mega'
        expected_result = {'size_spec': [65, 'mega']}
        assertParserResultDictFalse(logging_chan_file_path_size_element,
                                    test_string,
                                    expected_result, '"mega" s not a valid size legend')
        test_string = 'size 128 mega'
        expected_result = {'size_spec': [128, 'mega']}
        assertParserResultDictFalse(logging_chan_file_path_size_element,
                                    test_string,
                                    expected_result, '"mega" is not a valid size legend')

    def test_isc_logging_chan_file_path_element_passing(self):
        """ Clause logging; Element File path; passing mode """
        test_string = 'file "simple-relative-filename"'
        expected_result = {'path_name': '"simple-relative-filename"'}
        assertParserResultDictTrue(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')
        test_string = 'file "/tmp/unquoted-key_id"'
        expected_result = {'path_name': '"/tmp/unquoted-key_id"'}
        assertParserResultDictTrue(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')
        test_string = 'file "/tmp/spaced-out key_id"'
        expected_result = {'path_name': '"/tmp/spaced-out key_id"'}
        assertParserResultDictTrue(logging_chan_file_path_element,
                           test_string,
                           expected_result, 'did not detect missing semicolon')
#        test_string = 'file /tmp/"spaced dir"/spaced-outkey_id'   # TODO: Either get this working or go generic-string
#        expected_result = {'path_name': '/tmp/spaced dir/spaced-outkey_id'}
#        assertParserResultDictTrue(logging_chan_file_path_element,
#                                   test_string,
#                                   expected_result, 'did not detect missing semicolon')
        test_string = "file '/tmp/spaced-out key_id2'"
        expected_result = {'path_name': "'/tmp/spaced-out key_id2'"}
        assertParserResultDictTrue(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')
        test_string = 'file \'/dev/null\''
        expected_result = {'path_name': '\'/dev/null\''}
        assertParserResultDictTrue(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_file_path_element_failing(self):
        """ Clause logging; Element File path; failing mode """
        test_string = 'file "/control_r\rsubdir/unquoted-key_id"'
        expected_result = {'path_name': '"/control_r\rsubdir/unquoted-key_id"'}
        assertParserResultDictFalse(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')
        test_string = 'file /control_b\bsubdir/unquoted-key_id'
        expected_result = {'path_name': '/control_b\bsubdir/unquoted-key_id'}
        assertParserResultDictFalse(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')
        test_string = 'file /gappy subdir/unquoted-key_id'
        expected_result = {'path_name': '/gappy subdir/unquoted-key_id'}
        assertParserResultDictFalse(logging_chan_file_path_element,
                                   test_string,
                                   expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_file_method_passing(self):
        """ Clause logging; Element File Method; passing mode """
        test_string = 'file "unquoted-key_id";'
        expected_result = {'path_name': '"unquoted-key_id"'}
        assertParserResultDictTrue(logging_chan_file_method,
                                    test_string,
                                    expected_result)
        test_string = 'syslog syslog;'
        expected_result = {'facility': 'syslog'}
        assertParserResultDictTrue(logging_chan_file_method,
                                    test_string,
                                    expected_result)
        test_string = 'syslog daemon;'
        expected_result = {'facility': 'daemon'}
        assertParserResultDictTrue(logging_chan_file_method,
                                    test_string,
                                    expected_result)
        test_string = 'stderr;'
        expected_result = {'io': 'stderr'}
        assertParserResultDictTrue(logging_chan_file_method,
                                    test_string,
                                    expected_result)
        test_string = 'null;'
        expected_result = {'io': 'null'}
        assertParserResultDictTrue(logging_chan_file_method,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_file_method_failing(self):
        """ Clause logging; Element File Method; failing mode """
        test_string = 'stdin;'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_method,
                                    test_string,
                                    expected_result, 'did not detect missing semicolon')
        test_string ='stdout;'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_method,
                                    test_string,
                                    expected_result, 'did not detect missing semicolon')
        test_string ='zero;'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_method,
                                    test_string,
                                    expected_result, 'did not detect missing semicolon')
        test_string ='file nutz;file-with-semicolon.type;'
        expected_result = {}
        assertParserResultDictFalse(logging_chan_file_method,
                                    test_string,
                                    expected_result, 'did not detect missing semicolon')
        test_string = 'syslog warning;'
        expected_result = {'io': 'null'}
        assertParserResultDictFalse(logging_chan_file_method,
                                    test_string,
                                    expected_result, 'did not detect missing semicolon')

    def test_isc_logging_chan_severity_select_passing(self):
        """ Clause logging; Type Channel Severity; passing """
        test_string = "debug"
        expected_result = {'debug': []}
        assertParserResultDictTrue(logging_chan_syslog_severity_select,
                                   test_string,
                                   expected_result)
        test_string = "debug 2"
        expected_result = {'debug': [2]}
        assertParserResultDictTrue(logging_chan_syslog_severity_select,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_severity_element_passing(self):
        """ Clause logging; Element Channel Severity; passing mode """
        test_string = 'severity critical;'
        expected_result = {'severity': ['critical']}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity error;'
        expected_result = {'severity': ['error']}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity warning;'
        expected_result = {'severity': ['warning']}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity notice;'
        expected_result = {'severity': ['notice']}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity info;'
        expected_result = {'severity': ['info']}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity debug;'
        expected_result = {'severity': {'debug': []}}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity debug 1;'
        expected_result = {'severity': {'debug': [1]}}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)
        test_string = 'severity warning;'
        expected_result = {'severity': ['warning']}
        assertParserResultDictTrue(logging_chan_syslog_severity_element,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_severity_element_failing(self):
        """ Clause logging; Element Channel Severity; failing mode """
        test_data = [
        ]
        test_string = 'severity warn;'
        expected_result = {'severity': ['warn']}
        assertParserResultDictFalse(logging_chan_syslog_severity_element,
                                    test_string,
                                    expected_result)
        test_string = 'severity debug high;'
        expected_result = {'severity': {'debug': ['high']}}
        assertParserResultDictFalse(logging_chan_syslog_severity_element,
                                    test_string,
                                    expected_result)
        test_string = 'severity dire_emergency;'
        expected_result = {'severity': ['dire_emergency']}
        assertParserResultDictFalse(logging_chan_syslog_severity_element,
                                    test_string,
                                    expected_result)
        test_string = 'severity debug on;'
        expected_result = {'severity': {'debug': ['on']}}
        assertParserResultDictFalse(logging_chan_syslog_severity_element,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_print_category_element_passing(self):
        """ Clause logging; Element Channel Print Category; passing mode """
        test_data = [
        ]
        test_string = 'print-category yes;'
        expected_result = {'print_category': 'yes'}
        assertParserResultDictTrue(logging_chan_print_category_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-category 1;'
        expected_result = {'print_category': '1'}
        assertParserResultDictTrue(logging_chan_print_category_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-category False;'
        expected_result = {'print_category': 'False'}
        assertParserResultDictTrue(logging_chan_print_category_element,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_print_category_element_failing(self):
        """ Clause logging; Element Channel Print Category; failing mode """
        test_data = [
        ]
        test_string = 'print_category yes;'  # underscore used instead of an hyphen
        expected_result = {'print_category': 'False'}
        assertParserResultDictFalse(logging_chan_print_category_element,
                                    test_string,
                                    expected_result)
        test_string = 'print category yes;'  # missing hyphen
        expected_result = {'print_category': 'False'}
        assertParserResultDictFalse(logging_chan_print_category_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-categories yes'  # plural form used instead of singular
        expected_result = {'print_category': 'False'}
        assertParserResultDictFalse(logging_chan_print_category_element,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_print_severity_element_passing(self):
        """ Clause logging; Element Channel Print Severity; passing mode """
        test_string = 'print-severity no;'
        expected_result = {'print_severity': 'no'}
        assertParserResultDictTrue(logging_chan_print_severity_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-severity 1;'
        expected_result = {'print_severity': '1'}
        assertParserResultDictTrue(logging_chan_print_severity_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-severity True;'
        expected_result = {'print_severity': 'True'}
        assertParserResultDictTrue(logging_chan_print_severity_element,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_print_severity_element_failing(self):
        """ Clause logging; Element Channel Print Severity; failing mode """
        test_string = 'print-severity severe;'
        expected_result = {'print_severity': 'severe'}
        assertParserResultDictFalse(logging_chan_print_severity_element,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_print_time_element_passing(self):
        """ Clause logging; Element Channel Print Time; passing mode """
        test_string = 'print-time yes;'
        expected_result = {'print_time': 'yes'}
        assertParserResultDictTrue(logging_chan_print_time_element,
                                   test_string,
                                   expected_result)
        test_string = 'print-time 1;'
        expected_result = {'print_time': '1'}
        assertParserResultDictTrue(logging_chan_print_time_element,
                                   test_string,
                                   expected_result)
        test_string = 'print-time True;'
        expected_result = {'print_time': 'True'}
        assertParserResultDictTrue(logging_chan_print_time_element,
                                   test_string,
                                   expected_result)
        test_string = 'print-time local;'
        expected_result = {'print_time': 'local'}
        assertParserResultDictTrue(logging_chan_print_time_element,
                                   test_string,
                                   expected_result)
        test_string = 'print-time iso8601;'
        expected_result = {'print_time': 'iso8601'}
        assertParserResultDictTrue(logging_chan_print_time_element,
                                   test_string,
                                   expected_result)
        test_string = 'print-time iso8601-utc;'
        expected_result = {'print_time': 'iso8601-utc'}
        assertParserResultDictTrue(logging_chan_print_time_element,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_print_time_element_failing(self):
        """ Clause logging; Element Channel Print Time; failing mode """
        test_string = 'print-time off;'
        expected_result = {'print_time': 'off'}
        assertParserResultDictFalse(logging_chan_print_time_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-time zero;'
        expected_result = {'print_time': 'zero'}
        assertParserResultDictFalse(logging_chan_print_time_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-time none;'
        expected_result = {'print_time': 'none'}
        assertParserResultDictFalse(logging_chan_print_time_element,
                                    test_string,
                                    expected_result)
        test_string = 'print-time iso8601-est;'
        expected_result = {'print_time': 'iso8601-est'}
        assertParserResultDictFalse(logging_chan_print_time_element,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_method_option_set_passing(self):
        """ Clause logging; Set Method; passing mode """
        test_string = 'print-time 1;'
        expected_result = {'print_time': '1'}
        assertParserResultDictTrue(logging_chan_method_option_set,
                                   test_string,
                                   expected_result)
        test_string = 'buffered 0;'
        expected_result = {'buffered': '0'}
        assertParserResultDictTrue(logging_chan_method_option_set,
                                   test_string,
                                   expected_result)
        test_string = 'print-severity True;'
        expected_result = {'print_severity': 'True'}
        assertParserResultDictTrue(logging_chan_method_option_set,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_method_option_series_passing(self):
        """ Clause logging; Series Method; passing mode """
        test_string = 'print-time 1; buffered 0; print-severity True;'
        expected_result = {'print_time': '1', 'buffered': '0', 'print_severity': 'True'}
        assertParserResultDictTrue(logging_chan_method_option_series,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_method_option_series_failing(self):
        """ Clause logging; Series Method; failing mode """
        test_string = 'print-time 2; buffered -1; print-severity True;'
        expected_result = {'print_time': '1', 'buffered': '0', 'print_severity': 'True'}
        assertParserResultDictFalse(logging_chan_method_option_series,
                                    test_string,
                                    expected_result)

    def test_isc_logging_chan_method_element_passing(self):
        """ Clause logging; Element Channel Method; passing mode """
        test_string = 'syslog mail;'
        expected_result = {'facility': 'mail'}
        assertParserResultDictTrue(logging_chan_method_element,
                                    test_string,
                                    expected_result)
        test_string = 'syslog local0;'
        expected_result = {'facility': 'local0'}
        assertParserResultDictTrue(logging_chan_method_element,
                                   test_string,
                                   expected_result)

    def test_isc_logging_chan_method_element_failing(self):
        """ Clause logging; Element Channel Method; failing mode """
        test_string = 'files /tmp/x size 30M; severity ludicrous; print-time yes;}; };'
        expected_result = {'files': 'local0'}
        assertParserResultDictFalse(logging_chan_method_element,
                                    test_string,
                                    expected_result)
        test_string = 'syslog hacked;'
        expected_result = {'facility': 'hacked'}
        assertParserResultDictFalse(logging_chan_method_element,
                                    test_string,
                                    expected_result)
        test_string = 'syslog warning;'
        expected_result = {'facility': 'warning'}
        assertParserResultDictFalse(logging_chan_method_element,
                                    test_string,
                                    expected_result)

    def test_isc_logging_stmt_channel_passing(self):
        """ Clause logging; Statement Channel; passing mode """
        test_string = 'channel bleep { file "/tmp/x" size 38M; severity warning;};'
        expected_result = { 'channel': [ { 'channel_name': 'bleep',
                 'path_name': '"/tmp/x"',
                 'severity': ['warning'],
                 'size_spec': [38, 'M']}]}
        assertParserResultDictTrue(logging_stmt_channel_set,
                                   test_string,
                                   expected_result)

    def test_isc_logging_stmt_channel2_passing(self):
        test_string = 'channel klaxon { file "/tmp/x" size 38M; };'
        expected_result = { 'channel': [ { 'channel_name': 'klaxon',
                 'path_name': '"/tmp/x"',
                 'size_spec': [38, 'M']}]}
        assertParserResultDictTrue(logging_stmt_channel_set,
                                   test_string,
                                   expected_result)

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
        assertParserResultDictFalse(logging_stmt_channel_set,
                                    test_string,
                                    expected_result)

    def test_isc_clause_logging_logging_stmt_category_passing(self):
        """ Clause logging; Statement Category; passing mode """
        test_string = 'category default { default_syslog; default_debug; };'
        expected_result = { 'category_group': [ { 'categories': [ 'default_syslog',
                                        'default_debug'],
                        'category_group_name': 'default'}]}
        assertParserResultDictTrue(logging_stmt_category_set,
                                   test_string,
                                   expected_result)

    def test_isc_clause_logging_logging_stmt_category2_passing(self):
        test_string = 'category unmatched { null; };'
        expected_result = { 'category_group': [ { 'categories': ['null'],
                        'category_group_name': 'unmatched'}]}
        assertParserResultDictTrue(logging_stmt_category_set,
                                   test_string,
                                   expected_result)

    def test_isc_clause_logging_logging_stmt_category_failing(self):
        """ Clause logging; Statement Category; failing mode """
        test_string = 'category k l { b; c; d; };'
        expected_result = {
            'category_group': {
                'categories': ['b', 'c', 'd'],
                'category_group_name': 'k'}}
        assertParserResultDictFalse(logging_stmt_category_set,
                                    test_string,
                                    expected_result)

    def test_isc_clause_stmt_logging_passing(self):
        """ Clause logging; Statement Logging; passing mode """
        test_string = 'logging { channel siren { file "/tmp/x" size 30M; severity info; print-time yes;}; };'
        expected_result = { 'logging': [ { 'channel': [ { 'channel_name': 'siren',
                                'path_name': '"/tmp/x"',
                                'print_time': 'yes',
                                'severity': ['info'],
                                'size_spec': [30, 'M']}]}]}
        assertParserResultDictTrue(clause_stmt_logging_standalone,
                                   test_string,
                                   expected_result)

    def test_isc_clause_stmt_logging2_passing(self):
        test_string = 'logging { channel floodwatch { file "/tmp/x" size 30M; print-time yes; severity info;}; };'
        expected_result = { 'logging': [ { 'channel': [ { 'channel_name': 'floodwatch',
                                'path_name': '"/tmp/x"',
                                'print_time': 'yes',
                                'severity': ['info'],
                                'size_spec': [30, 'M']}]}]}
        assertParserResultDictTrue(clause_stmt_logging_standalone,
                                   test_string,
                                   expected_result)

    def test_isc_clause_stmt_logging3_passing(self):
        test_string = 'logging { channel tv { file "/tmp/x" size 30M; severity info; print-time yes;}; };'
        expected_result = { 'logging': [ { 'channel': [ { 'channel_name': 'tv',
                                'path_name': '"/tmp/x"',
                                'print_time': 'yes',
                                'severity': ['info'],
                                'size_spec': [30, 'M']}]}]}
        assertParserResultDictTrue(clause_stmt_logging_standalone,
                                   test_string,
                                   expected_result)

    def test_isc_clause_stmt_logging4_passing(self):
        test_string = 'logging { channel office_vpn { file "/tmp/x" size 42M; severity critical; print-time no;}; };'
        expected_result = { 'logging': [ { 'channel': [ { 'channel_name': 'office_vpn',
                                'path_name': '"/tmp/x"',
                                'print_time': 'no',
                                'severity': ['critical'],
                                'size_spec': [42, 'M']}]}]}
        assertParserResultDictTrue(clause_stmt_logging_standalone,
                                   test_string,
                                   expected_result)

    def test_isc_clause_stmt_logging_multiple_passing(self):
        """ Clause logging; Statement, Multiple; passing mode """

        test_string = 'logging { channel salesfolks { file "/tmp/sales.log" size 5M; severity info; print-time no;};'\
        ' channel accounting { file "/tmp/acct.log" size 30M; severity info; print-time no;};'\
        ' channel badguys { file "/tmp/alert" size 255G; severity debug 77; print-time yes;}; };'
        expected_result = { 'logging': [ { 'channel': [ { 'channel_name': 'salesfolks',
                                'path_name': '"/tmp/sales.log"',
                                'print_time': 'no',
                                'severity': ['info'],
                                'size_spec': [5, 'M']}]},
               { 'channel': [ { 'channel_name': 'accounting',
                                'path_name': '"/tmp/acct.log"',
                                'print_time': 'no',
                                'severity': ['info'],
                                'size_spec': [30, 'M']}]},
               { 'channel': [ { 'channel_name': 'badguys',
                                'path_name': '"/tmp/alert"',
                                'print_time': 'yes',
                                'severity': {'debug': [77]},
                                'size_spec': [255, 'G']}]}]}
        assertParserResultDictTrue(clause_stmt_logging_standalone,
                                   test_string,
                                   expected_result)

    def test_isc_logging_clause_stmt_failing(self):
        """ Clause logging; Statement Logging; failing mode """
        test_string = 'logging { channel cb { files "/tmp/x" size 30M; severity info; print-time yes;}; };'
        expected_result = {}
        assertParserResultDictFalse(clause_stmt_logging_standalone,
                                    test_string,
                                    expected_result)
        test_string = 'logging { channel trucker { file "/tmp/x" size 30M; print__ime yes; severity info;}; };'
        expected_result = {}
        assertParserResultDictFalse(clause_stmt_logging_standalone,
                                    test_string,
                                    expected_result)


# TODO: Needs unit test for
#
#       parse_me(logging_chan_syslog_severity_element, 'severity critical;', True)
#       parse_me(logging_chan_syslog_severity_element, 'severity debug 1;', True)

