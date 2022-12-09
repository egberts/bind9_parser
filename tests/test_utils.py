#!/usr/bin/env python3
"""
File: test_utils
"""

import unittest
from pyparsing import pythonStyleComment, cppStyleComment
from bind9_parser.isc_utils import assert_parser_result_dict_true,\
    isc_boolean, isc_file_name, \
    dequotable_path_name, \
    acl_name, acl_name_dquotable, acl_name_squotable, \
    key_secret, key_id, key_id_keyword_and_name_pair, \
    view_name, view_name_dquotable, view_name_squotable, \
    zone_name, zone_name_dquotable, zone_name_squotable, \
    fqdn_name, krb5_principal_name, \
    check_options, \
    filename_base, size_spec, path_name, algorithm_name,\
    algorithm_name_list_set, algorithm_name_list_series, \
    key_id_list_series, primary_id


class TestConfigUtils(unittest.TestCase):
    """ ISC Utilities """

    def test_isc_utils_boolean_passing(self):
        """ ISC-styled <boolean>, passing"""
        test_data = [
            'yes',
            'no',
            'YES',
            '0',
            '1',
            'True',
            'FALSe',
        ]
        result = isc_boolean.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_boolean_failing(self):
        """ ISC-styled <boolean>, failing"""
        test_data = [
            'yeah',
            'nope',
            'YESSS!',
            'nada',
            'onesie',
            'illogically-true',
            'patently-false',
        ]
        result = isc_boolean.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_utils_filename_base_passing(self):
        """File name convention, bsae character sets (UNIX-only), passing"""
        test_data = [
            "Readablea_file.type",
            "unReadableb_file.type",
        ]
        result = filename_base.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_filename_base_failing(self):
        """File name convention, bsae character sets (UNIX-only), failing"""
        test_data = [
            "'Readable a_file.type'",
            "\"unReadable b_file.type\"",
            "unReadable\tb_file.type",
        ]
        result = filename_base.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_utils_isc_file_name_passing(self):
        """ ISC Utilities; Type isc_file_name; passing """
        test_data = [
            'filenamewithoutatype',
            'filename.type',
            'file_expanded.type',
            'file-hyphenated.type',
            "'Readable a_file.type'",
            'a_file.type',
            'long_file.type',
            '"a_file with-dash.type"',
            "'Readable a_file.type'",
            "'Readable a_file;.type'",
            "'Readable \"a_file.type'",
        ]
        result = isc_file_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_isc_file_name_dict_passing(self):
        """ ISC Utilities; Type isc_file_name; failing """
        test_data = 'filenamewithoutatype'
        expected_result = {'filename': 'filenamewithoutatype'}
        assert_parser_result_dict_true(
            isc_file_name,
            test_data,
            expected_result
        )

    def test_isc_utils_isc_file_name_failing(self):
        """ ISC Utilities; Type isc_file_name; failing """
        test_data = [
            'fil/enamewithoutatype',
            'fil"e"name.type',
            'file_expanded.type"',
            "'file-hyphenated.type",
        ]
        result = isc_file_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_utils_isc_dequotable_path_name_passing(self):
        """ ISC Utilities; Type dequotable_path_name; passing """
        test_data = [
            '"fil/enamewithoutatype"',
            "'fil\"e\"name.type'",
            '\'a/b/c/d/e/f/g/h/file_expanded.type"\'',
            "\"file-hyphenated.type\"",
        ]
        result = dequotable_path_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_isc_dequotable_path_name_assert_passing(self):
        """ ISC Utilities; Type dequotable_path_name assert; passing """
        assert_parser_result_dict_true(
            dequotable_path_name,
            '"fil/enamewithoutatype"',
            {'path_name': 'fil/enamewithoutatype'}
        )

    def test_isc_utils_path_name_passing(self):
        """Path name convention (UNIX-only)"""
        test_data = [
            'a_file.type',
            'directory/b_file.type2',
            'directory/subdir/c_file.type3',
            'directory3/e_file.type5',
            "'directory/\"fi le\".t;ype'",
            "'Readable \"f_file.type6'",
            "'directory/\"fi le_name\".type'",
            #            "directory/\"fi le\"_name.type",  # FAILING, TODO unable to quote a middle subdirectory name
        ]
        result = path_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_path_name_dict_passing(self):
        """ ISC Utilities; Type path_name; List/Dict; passing """
        test_data = 'directory/subdir/g_file.type9'
        expected_result = {'path_name': 'directory/subdir/g_file.type9'}
        assert_parser_result_dict_true(path_name, test_data, expected_result)

    def test_isc_utils_path_name_failing(self):
        """Path name convention (UNIX-only)"""
        # TODO: Doesn't work with 'top_dir/"sub directory"_two/a_file.type'
        test_data = [
            "'file-hyphenated.type",
            'directory/a_file.t;ype',  # any semicolon in a filename must be quoted in ISC config files
        ]
        result = path_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_acl_name_passing(self):
        """ ISC Utilities; Type ACL Name; passing """
        test_data = [
            'myaclname',
            'my_acl_name',
            'my-dashed-acl-name',
            'unquotedaclname',
            '"dquoted-acl_name"',
            "'squoted-acl_name'"
        ]
        result = acl_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_acl_name_dict_passing(self):
        """ ISC Utilities; Type acl_name; List/Dict; passing"""
        test_data = 'my-dashed-acl-name'
        expected_result = {'acl_name': 'my-dashed-acl-name'}
        assert_parser_result_dict_true(acl_name,
                                       test_data,
                                       expected_result)

    def test_isc_acl_name_failing(self):
        """ ISC Utilities; Type acl_name; failing """
        test_data = [
            'acl_name890123456789012345678901234567890123456789012345678901234567890123',
        ]
        result = acl_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_acl_names_dquoting_failed(self):
        """ ISC Utilities; Type ACL Name; Double-Quote; failing """
        test_data = [
            '"double-quote-not-allowed',
            'double-quote-not-allowed"',
            'double-"quote"-not-allowed'
        ]
        result = acl_name_dquotable.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_acl_names_squoting_passing(self):
        """ ISC Utilities; Type ACL Name; Single Quote; passing """
        test_data = ["'single-quote-allowed-to-pass'"]
        result = acl_name_squotable.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_acl_names_squoting_failing(self):
        """ ISC Utilities; Type ACL Name; failing """
        test_data = ["single-'quote'-purposely-failing"]
        result = acl_name_squotable.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_key_secret_passing(self):
        """ ISC Utilities; Type key_secret; passing """
        test_data = [
            'ABCDEF0123458',
            "'ABCDEF0123458'",
            '"ABCDEF0123458"',
        ]
        result = key_secret.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_secret_dict_passing(self):
        """ ISC Utilities; Type key_secret; List/Dict; passing """
        test_data = 'ABCDEF0123456'
        expected_result = {'key_secret': 'ABCDEF0123456'}
        assert_parser_result_dict_true(key_secret,
                                       test_data,
                                       expected_result)

    def test_isc_key_secret_failing(self):
        """ ISC Utilities; Type Key Secret; failing """
        test_data = ["bad_key_secret_ABCDEFGH&^%$"]
        result = key_secret.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_key_id_passing(self):
        """ ISC Utilities; Type key_id; passing """
        test_data = [
            'ABCDEF0123458',
            'ABC_EF0123458',
            'ABC_EF0-23458',
            'ABC_EF0-23458',
            "'ABCD_F0123458'",
            '"ABCDEF01-3458"',
            '"ABCD_F0123458"',
            "'ABCDEF01-3458'",
        ]
        result = key_id.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_key_id_and_name_element_dict_passing(self):
        """ ISC Utilities; Type key_id_keyword_and_name_pair; List/Dict; passing """
        test_data = 'key ZYX_KEY'
        expected_result = {'key_id': 'ZYX_KEY'}
        assert_parser_result_dict_true(key_id_keyword_and_name_pair,
                                       test_data,
                                       expected_result)

    def test_isc_key_id_failing(self):
        """ ISC Utilities; Type key_id; failing """
        test_data = ["bad_key_id_ABCDEFGH&^%$"]
        result = key_id.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_view_name_passing(self):
        """ ISC Utilities; Type view_name; Quotes; passing """
        test_data = [
            'red_view',
            'red__view',
            'red_view-dmz',
            "\'green_view\'",
            '"dmz-view"',
            '"vps-view"',
            "'docker-view'",
            'dmz',
            ''"red"'',
            "\'green\'",
        ]
        result = view_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_view_name_dict_passing(self):
        """ ISC Utilities; Type view_name; List/Dict; passing """
        test_data = 'red_zone'
        expected_result = {'view_name': 'red_zone'}
        assert_parser_result_dict_true(view_name,
                                       test_data,
                                       expected_result)

    def test_isc_view_name_failing(self):
        """ ISC Utilities; Type view_name; Quotes; failing """
        test_data = [
            "bad_view_name/DEFGH&^%$",  # only slash fails
            'r!3d',  # exclamation is used only in Address-Match-List context
            'red zone',  # must be quoted
            'lone-double-quote\"',  # Cannot have a lone quote symbol
            '\"lone-double-quote',  # Cannot have a lone quote symbol
            'lone-single-quote\'',
        ]
        result = view_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_view_name_dquoted_passing(self):
        """ ISC Utilities; Type View Name; Double-Quote; passing """
        test_data = [
            '"red_view"'
        ]
        result = view_name_dquotable.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_view_name_squoted_passing(self):
        """ ISC Utilities; Type View Name; Single-Quote; passing """
        """ Clause view; Type view_name_squote; passing """
        test_data = [
            "'red_view'"
        ]
        result = view_name_squotable.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_name_dquoted_passing(self):
        """ ISC Utilities; Type Zone Name; Double-Quote; passing """
        test_data = [
            '"red_zone"'
        ]
        result = zone_name_dquotable.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])
        assert_parser_result_dict_true(
            zone_name_dquotable,
            '"example.com."',
            {'zone_name': '"example.com."'}
        )

    def test_isc_zone_name_squoted_passing(self):
        """ ISC Utilities; Type Zone Name; Single-Quote; passing """
        test_data = [
            "'red_zone'"
        ]
        result = zone_name_squotable.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_name_passing(self):
        """ ISC Utilities; Type Zone Name; passing """
        test_data = [
            'red',
            'red_zone',
            'red_zone-dmz',
        ]
        result = zone_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_name_dict_passing(self):
        """ ISC Utilities; Type zone_name; List/Dict; passing """
        test_data = 'white-lab.example.net'
        expected_result = {'zone_name': 'white-lab.example.net'}
        assert_parser_result_dict_true(
            zone_name,
            test_data,
            expected_result)

    def test_isc_zone_name_quoted_passing(self):
        """ ISC Utilities; Type Zone Name; Quoted; passing """
        test_data = [
            "\'GHIJ_KL987656\'",
            '\"KLMNOP23-5678\"',
            '\"QRST_U9012345\"',
            "\'UVWXYZ12-4567\'",
        ]
        result = zone_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_zone_name_failing(self):
        """ ISC Utilities; Type Zone Name; failing """
        test_data = ["bad_key_id/ABCDEFGH&^%$"]
        result = zone_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_fqdn_name_passing(self):
        """ ISC Utilities; Type FQDN name; passing """
        test_data = [
            'mylocalhost',
            'laptop.home',
            'dashed-hostname.local',
            'www.example.com',
            "'quoted.fqdn.org'",
            '"john.rocks"',
            '"dquoted.fqdn.us"',
            "'squoted.fqdn.eu'",
            'absolute.fqdn.nz.',
        ]
        result = fqdn_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_fqdn_name_dict_passing(self):
        """ ISC Utilities; Type fqdn_name; List/Dict; passing """
        test_data = 'finance-dept.example.com'
        expected_result = {'fqdn_name': 'finance-dept.example.com'}
        assert_parser_result_dict_true(fqdn_name,
                                       test_data,
                                       expected_result)

    def test_isc_fqdn_name_failing(self):
        """ ISC Utilities; Type FQDN name; failing """
        test_data = ["www.weird-hostname#a.com"]
        result = fqdn_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_krb5_principal_name_base_passing(self):
        """ ISC Utilities; Type KRB5 Principal Name; passing """
        test_data = [
            "janet@quoted.fqdn.org",
        ]
        result = krb5_principal_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    # no instance in KRB5 principal name (it is OK)
    def test_isc_krb5_principal_name_instance_passing(self):
        """ ISC Utilities; Type KRB5 Principal Name; passing """
        test_data = [
            "instance/quoted.fqdn.org",
        ]
        result = krb5_principal_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_krb5_principal_name_passing(self):
        """ ISC Utilities; Type KRB5 Principal Name; passing """
        test_data = [
            'jill@mylocalhost',
            'joe@laptop.home',
            'jim@dashed-hostname.local',
            'jerry@www.example.com',
            "\'janet@quoted.fqdn.org\'",
            '\"admin@john.rocks\"',
            '"sales@dquoted.fqdn.us"',
            "'webmaster@squoted.fqdn.eu'",
            'root@absolute.fqdn.nz.',
            'admin/mymachine.home@absolute.fqdn.nz.',
        ]
        result = krb5_principal_name.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_krb5_principal_name_dict_passing(self):
        """ ISC Utilities; Type krb5_principal_name; List/Dict; passing """
        test_data = 'ADMIN@ATHENA.MIT.EDU'
        expected_result = {
            'primary': 'ADMIN',
            'principal': 'ADMIN@ATHENA.MIT.EDU',
            'realm': 'ATHENA.MIT.EDU'}
        assert_parser_result_dict_true(krb5_principal_name,
                                       test_data,
                                       expected_result)
        test_data = 'ADMIN/FINANCE_DEPT@ATHENA.MIT.EDU'
        expected_result = {
            'instance': 'FINANCE_DEPT',
            'primary': 'ADMIN',
            'principal': 'ADMIN/FINANCE_DEPT@ATHENA.MIT.EDU',
            'realm': 'ATHENA.MIT.EDU'}
        assert_parser_result_dict_true(krb5_principal_name,
                                       test_data,
                                       expected_result)

    def test_isc_krb5_principal_name_failing(self):
        """ ISC Utilities; Type KRB5 Principal Name; failing """
        test_data = ["www.weird-hostname#a.com"]
        result = krb5_principal_name.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_utils_size_spec_passing(self):
        """ ISC Utilities; Type SizeSpec; passing """
        test_data = [
            'unlimited',
            'default',
            '1',
            '0',
            '100',
            '1K',
            '2k',
            '3M',
            '4m',
            '5G',
            '6g',
        ]
        result = size_spec.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_size_spec_dict_passing(self):
        """ ISC Utilities; Type size_spec; List/Dict; passing """
        test_data = "14M"
        expected_data = {'size': [14, 'M']}
        assert_parser_result_dict_true(size_spec, test_data, expected_data)

    def test_isc_utils_size_spec_failing(self):
        """ ISC Utilities; Type SizeSpec; failing """
        test_data = [
            '-1',
            '2 giga',
            '3Kb',
            '4kb',
            '1min',
            'limitless',
            'unlimit',
            'defaulted',
            'defaults',
        ]
        result = size_spec.runTests(test_data, failureTests=True)
        self.assertTrue(result[0])

    def test_isc_utils_check_options_failing(self):
        """ ISC Utilities; Type CheckOptions; passing """
        test_data = [
            'warn',
            'WARN',
            'WaRn',
            'fail',
            'FAIL',
            'fAiL',
            'ignore',
            'IGNORE',
            'ignOre',
        ]
        result = check_options.runTests(test_data, failureTests=False)
        self.assertTrue(result[0])

    def test_isc_utils_inline_comments_passing(self):

        test_string = """
        abc; // CPP-style comment
        def /* C-comment */ ;  # bash-styled
        ghi;"""
        expected_result = {'key_ids': ['abc', 'def', 'ghi']}  # Orders matter
        new_key_id_series = key_id_list_series.copy()
        new_key_id_series.ignore(cppStyleComment)
        new_key_id_series.ignore(pythonStyleComment)
        new_key_id_series.setWhitespaceChars(' \t')
        assert_parser_result_dict_true(new_key_id_series,
                                       test_string,
                                       expected_result,
                                        'Unable to handle inline comments.')

    def test_isc_utils_algorithm_name_passing(self):
        """ ISC Utilities; Type algorithm_name; passing """
        test_string = 'SHA512'
        expected_result = {'algorithm_name': 'SHA512'}
        assert_parser_result_dict_true(
            algorithm_name,
            test_string,
            expected_result)

    def test_isc_utils_algorithm_name_set_passing(self):
        """ ISC Utilities; Type algorithm_name_list_set; passing """
        test_string = 'SHA512;'
        expected_result = {'algorithm_name': 'SHA512'}
        assert_parser_result_dict_true(
            algorithm_name_list_set,
            test_string,
            expected_result)

    def test_isc_utils_algorithm_name_series_passing(self):
        """ ISC Utilities; Type algorithm_name_list_series; passing """
        test_string = 'SHA512; sha-128; dsa; rsa; ED448; ED25519;'
        expected_result = { 'algorithm_name': [ 'SHA512',
                                                'sha-128',
                                                'dsa',
                                                'rsa',
                                                'ED448',
                                                'ED25519']}
        assert_parser_result_dict_true(
            algorithm_name_list_series,
            test_string,
            expected_result)

    def test_isc_utils_primary_name_passing(self):
        """ ISC Utilities; Type primary_id; passing """
        assert_parser_result_dict_true(
            primary_id,
            'myprimary_name',
            {'primary_id': 'myprimary_name'}
            )

if __name__ == '__main__':
    unittest.main()
