
# tests/runner.py
import unittest

import test_acl
import test_aml
import test_clause_acl
import test_clause_controls
import test_clause_dlz
import test_clause_dyndb
import test_clause_key
import test_clause_logging
import test_clause_managed_keys
import test_clause_masters
import test_clause_options
import test_clauses
import test_clause_server
import test_clause_view
import test_clause_zone
import test_domain
import test_inet
import test_managed_keys
import test_options
import test_optview
import test_optviewserver
import test_optviewzone
import test_optviewzoneserver
import test_optzone
import test_rr
import test_server
import test_trusted_keys
import test_utils
import test_view
import test_viewzone
import test_zone

# initialize the test suite
loader = unittest.TestLoader()
suite  = unittest.TestSuite()

# add tests to the test suite
suite.addTests(loader.loadTestsFromModule(test_utils))
suite.addTests(loader.loadTestsFromModule(test_domain))
suite.addTests(loader.loadTestsFromModule(test_inet))
suite.addTests(loader.loadTestsFromModule(test_rr))

suite.addTests(loader.loadTestsFromModule(test_aml))

suite.addTests(loader.loadTestsFromModule(test_acl))
suite.addTests(loader.loadTestsFromModule(test_managed_keys))
suite.addTests(loader.loadTestsFromModule(test_options))
suite.addTests(loader.loadTestsFromModule(test_server))
suite.addTests(loader.loadTestsFromModule(test_trusted_keys))
suite.addTests(loader.loadTestsFromModule(test_view))
suite.addTests(loader.loadTestsFromModule(test_viewzone))
suite.addTests(loader.loadTestsFromModule(test_zone))

suite.addTests(loader.loadTestsFromModule(test_optview))
suite.addTests(loader.loadTestsFromModule(test_optviewserver))
suite.addTests(loader.loadTestsFromModule(test_optviewzone))
suite.addTests(loader.loadTestsFromModule(test_optviewzoneserver))
suite.addTests(loader.loadTestsFromModule(test_optzone))


suite.addTests(loader.loadTestsFromModule(test_clause_acl))
suite.addTests(loader.loadTestsFromModule(test_clause_controls))
suite.addTests(loader.loadTestsFromModule(test_clause_dlz))
suite.addTests(loader.loadTestsFromModule(test_clause_dyndb))
suite.addTests(loader.loadTestsFromModule(test_clause_key))
suite.addTests(loader.loadTestsFromModule(test_clause_logging))
suite.addTests(loader.loadTestsFromModule(test_clause_managed_keys))
suite.addTests(loader.loadTestsFromModule(test_clause_masters))
suite.addTests(loader.loadTestsFromModule(test_clause_options))
suite.addTests(loader.loadTestsFromModule(test_clause_server))
suite.addTests(loader.loadTestsFromModule(test_clause_view))
suite.addTests(loader.loadTestsFromModule(test_clause_zone))

suite.addTests(loader.loadTestsFromModule(test_clauses))
# initialize a runner, pass it your suite and run it
runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)
