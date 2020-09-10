#!/bin/bash

# Cannot make this 'python3 -m unittest -q tests.test_*' work
# But we can do filepath here
python3 -m unittest -q tests/test_*.py
#
# or could do instead:
#     py.test-3 -q -s tests/test_*.py
#     nosetest3 -q tests/test_*.py

# Specific unit testing:

# python3 -m unittest -q tests.test_acl
# python3 -m unittest -q tests.test_acl.TestACL
# python3 -m unittest tests.test_acl.TestACL.test_isc_acl_geoip_inet_group_failing

