#!/usr/bin/env python3
"""
File: test_clause_tls

Description:
  Performs unit test on the 'tls' clause 
  in isc_clause_tls.py source file.
    
  Statement Grammar:

    tls <string> {
        ca-file <quoted_string>;
        cert-file <quoted_string>;
        ciphers <string>;
        dhparam-file <quoted_string>;
        key-file <quoted_string>;
        prefer-server-ciphers <boolean>;
        protocols { <string>; ... };
        remote-hostname <quoted_string>;
        session-tickets <boolean>;
    };
"""

import unittest
from bind9_parser.isc_utils import assertParserResultDictTrue
from bind9_parser.isc_clause_tls import tls_stmt_ca_file_element, \
    tls_stmt_cert_file_element, tls_stmt_ciphers_element, tls_stmt_dhparam_file_element,\
    tls_stmt_key_file_element, tls_stmt_prefer_server_ciphers_element, tls_stmt_protocols_element,\
    tls_stmt_remote_hostname_element, tls_stmt_session_tickets_element,\
    tls_stmt_element_set, tls_stmt_element_series, clause_stmt_tls_standalone,\
    clause_stmt_tls_set, clause_stmt_tls_series


class TestClauseHttp(unittest.TestCase):
    """ Test Clause 'tls' """

    def test_tls_ca_file_passing(self):
        """ Test Clause 'tls'; 'ca-file'; passing """
        test_string = 'ca-file "/etc/bind/cakeys/stuff.pem";'
        expected_result = {'ca_file': '/etc/bind/cakeys/stuff.pem'}
        assertParserResultDictTrue(
            tls_stmt_ca_file_element,
            test_string,
            expected_result)

    def test_tls_cert_file_passing(self):
        """ Test Clause 'tls'; 'cert-file'; passing """
        test_string = "cert-file '/etc/pki/cacert.key';"
        expected_result = {'cert_file': '/etc/pki/cacert.key'}
        assertParserResultDictTrue(
            tls_stmt_cert_file_element,
            test_string,
            expected_result)

    def test_tls_ciphers_passing(self):
        """ Test Clause 'tls'; 'ciphers'; passing """
        test_string = 'ciphers aes256;'
        expected_result = {'ciphers': 'aes256'}
        assertParserResultDictTrue(
            tls_stmt_ciphers_element,
            test_string,
            expected_result)

    def test_tls_dhparam_file_passing(self):
        """ Test Clause 'tls'; 'dhparam-file'; passing """
        test_string = 'dhparam-file "dhparam.md5";'
        expected_result = {'dhparam_file': 'dhparam.md5'}
        assertParserResultDictTrue(
            tls_stmt_dhparam_file_element,
            test_string,
            expected_result)

    def test_tls_key_file_passing(self):
        """ Test Clause 'tls'; 'key-file'; passing """
        test_string = 'key-file "key.key";'
        expected_result = {'key_file': 'key.key'}
        assertParserResultDictTrue(
            tls_stmt_key_file_element,
            test_string,
            expected_result)

    def test_tls_prefer_server_ciphers_passing(self):
        """ Test Clause 'tls'; 'prefer-server-ciphers'; passing """
        test_string = 'prefer-server-ciphers no;'
        expected_result = {'prefer_server_ciphers': 'no'}
        assertParserResultDictTrue(
            tls_stmt_prefer_server_ciphers_element,
            test_string,
            expected_result)

    def test_tls_protocols_passing(self):
        """ Test Clause 'tls'; 'protocols'; passing """
        test_string = "protocols {  'TLSv1.2'; TLSv1.3; };"
        expected_result = {'protocols': ['TLSv1.2', 'TLSv1.3']}
        assertParserResultDictTrue(
            tls_stmt_protocols_element,
            test_string,
            expected_result)

    def test_tls_remote_hostname_passing(self):
        """ Test Clause 'tls'; 'remote-hostname'; passing """
        test_string = 'remote-hostname example.test;'
        expected_result = {'remote_hostname': 'example.test'}
        assertParserResultDictTrue(
            tls_stmt_remote_hostname_element,
            test_string,
            expected_result)

    def test_tls_session_tickets_passing(self):
        """ Test Clause 'tls'; 'session-tickets'; passing """
        test_string = 'session-tickets no;'
        expected_result = {'session_tickets': 'no'}
        assertParserResultDictTrue(
            tls_stmt_session_tickets_element,
            test_string,
            expected_result)

    def test_tls_stmt_element_set_ca_file_passing(self):
        """ Test Clause 'tls'; element set 'ca-file'; passing """
        test_string = 'ca-file "/etc/pki/tunnel/ca-cert.crt.pem";';
        expected_result = {'ca_file': '/etc/pki/tunnel/ca-cert.crt.pem'}
        assertParserResultDictTrue(
            tls_stmt_element_set,
            test_string,
            expected_result)

    def test_tls_stmt_element_set_cert_file_passing(self):
        """ Test Clause 'tls'; element set 'cert-file'; passing """
        test_string = 'cert-file "/etc/pki/tunnel/cert.crt.pem";'
        expected_result = {'cert_file': '/etc/pki/tunnel/cert.crt.pem'}
        assertParserResultDictTrue(
            tls_stmt_element_set,
            test_string,
            expected_result)

    def test_stmt_clause_tls_set_passing(self):
        """ Test Clause 'tls'; element set 'ciphers'; passing """
        test_string = "ciphers 'aes256-sha256';"
        expected_result = {'ciphers': 'aes256-sha256'}
        assertParserResultDictTrue(
            tls_stmt_element_set,
            test_string,
            expected_result)

    def test_stmt_clause_tls_element_series_passing(self):
        """ Test Clause 'tls'; element series; passing """
        test_string = """cert-file '/etc/pki/cacert.key';
    remote-hostname example.test;
    ca-file "/etc/bind/cakeys/stuff.pem";
    key-file "key.key";
    session-tickets no;
    ciphers aes256;
    dhparam-file "dhparam.md5";
    protocols { TLSv1.2; 'TLSv1.3'; };
    prefer-server-ciphers yes;
    cert-file '/etc/pki/cacert.key'; """
        expected_result = { 'ca_file': '/etc/bind/cakeys/stuff.pem',
  'cert_file': '/etc/pki/cacert.key',
  'ciphers': 'aes256',
  'dhparam_file': 'dhparam.md5',
  'key_file': 'key.key',
  'prefer_server_ciphers': 'yes',
  'protocols': ['TLSv1.2', 'TLSv1.3'],
  'remote_hostname': 'example.test',
  'session_tickets': 'no'}
        assertParserResultDictTrue(
                tls_stmt_element_series,
                test_string,
                expected_result)

    def test_clause_stmt_tls_standalone_passing(self):
        """ Test Clause 'tls'; statement standalone; passing """
        test_string = """
    tls work_from_home {
        ca-file "/etc/pki/wfh/ca-cert.crt.pem";
        cert-file "/etc/pki/wfh/cert.crt.pem";
        ciphers 'aes256-sha256';
        dhparam-file "/etc/pki/wfh/dhparam.md5";
        key-file "/etc/pki/wfh/cert.key.pem";
        prefer-server-ciphers yes;
        protocols { 'TLSv1.2'; 'TLSv1.3'; };
        remote-hostname "example.test";
        session-tickets yes;
        };
    """
        assertParserResultDictTrue(
            clause_stmt_tls_standalone,
            test_string,
            {'tls': [{'ca_file': '/etc/pki/wfh/ca-cert.crt.pem',
                      'cert_file': '/etc/pki/wfh/cert.crt.pem',
                      'ciphers': 'aes256-sha256',
                      'dhparam_file': '/etc/pki/wfh/dhparam.md5',
                      'key_file': '/etc/pki/wfh/cert.key.pem',
                      'prefer_server_ciphers': 'yes',
                      'protocols': ['TLSv1.2', 'TLSv1.3'],
                      'remote_hostname': '"example.test"',
                      'session_tickets': 'yes',
                      'tls_name': 'work_from_home'}]}
            )

        """########################################################"""

    def test_clause_stmt_tls_series_passing(self):
        """ Test Clause 'tls'; series; passing """
        test_string = """
tls work_from_home {
    ca-file "/etc/pki/wfh/ca-cert.crt.pem";
    cert-file "/etc/pki/wfh/cert.crt.pem";
    ciphers 'aes256-sha256';
    dhparam-file "/etc/pki/wfh/dhparam.md5";
    key-file "/etc/pki/wfh/cert.key.pem";
    prefer-server-ciphers yes;
    protocols { 'TLSv1.2'; 'TLSv1.3'; };
    remote-hostname "example.test";
    session-tickets yes;
    };
tls public_tunnel {
    ca-file "/etc/pki/tunnel-public/ca-cert.crt.pem";
    cert-file "/etc/pki/tunnel-public/cert.crt.pem";
    ciphers 'aes256-sha256';
    dhparam-file "/etc/pki/tunnel-public/dhparam.md5";
    key-file "/etc/pki/tunnel-public/cert.key.pem";
    prefer-server-ciphers yes;
    protocols { 'TLSv1.2'; 'TLSv1.3'; };
    remote-hostname "example.test";
    session-tickets yes;
    };
tls private_tunnel {
    ca-file "/etc/pki/tunnel-private/ca-cert.crt.pem";
    cert-file "/etc/pki/tunnel-private/cert.crt.pem";
    ciphers 'aes256-sha256';
    dhparam-file "/etc/pki/tunnel-private/dhparam.md5";
    key-file "/etc/pki/tunnel-private/cert.key.pem";
    prefer-server-ciphers yes;
    protocols { 'TLSv1.2'; 'TLSv1.3'; };
    remote-hostname "example.test";
    session-tickets yes;
    };
"""
        assertParserResultDictTrue(
            clause_stmt_tls_series,
            test_string,
            {'tls': [{'ca_file': '/etc/pki/wfh/ca-cert.crt.pem',
                      'cert_file': '/etc/pki/wfh/cert.crt.pem',
                      'ciphers': 'aes256-sha256',
                      'dhparam_file': '/etc/pki/wfh/dhparam.md5',
                      'key_file': '/etc/pki/wfh/cert.key.pem',
                      'prefer_server_ciphers': 'yes',
                      'protocols': ['TLSv1.2', 'TLSv1.3'],
                      'remote_hostname': '"example.test"',
                      'session_tickets': 'yes',
                      'tls_name': 'work_from_home'},
                     {'ca_file': '/etc/pki/tunnel-public/ca-cert.crt.pem',
                      'cert_file': '/etc/pki/tunnel-public/cert.crt.pem',
                      'ciphers': 'aes256-sha256',
                      'dhparam_file': '/etc/pki/tunnel-public/dhparam.md5',
                      'key_file': '/etc/pki/tunnel-public/cert.key.pem',
                      'prefer_server_ciphers': 'yes',
                      'protocols': ['TLSv1.2', 'TLSv1.3'],
                      'remote_hostname': '"example.test"',
                      'session_tickets': 'yes',
                      'tls_name': 'public_tunnel'},
                     {'ca_file': '/etc/pki/tunnel-private/ca-cert.crt.pem',
                      'cert_file': '/etc/pki/tunnel-private/cert.crt.pem',
                      'ciphers': 'aes256-sha256',
                      'dhparam_file': '/etc/pki/tunnel-private/dhparam.md5',
                      'key_file': '/etc/pki/tunnel-private/cert.key.pem',
                      'prefer_server_ciphers': 'yes',
                      'protocols': ['TLSv1.2', 'TLSv1.3'],
                      'remote_hostname': '"example.test"',
                      'session_tickets': 'yes',
                      'tls_name': 'private_tunnel'}]}
        )


if __name__ == '__main__':
    unittest.main()
