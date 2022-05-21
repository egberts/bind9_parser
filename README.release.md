To create a Python3 package that is compliant with PEP 517:

```shell
cd bind9_parser
python3 -mbuild
```
Outputs the following:
```console
Collecting setuptools>=40.8.0
  Using cached setuptools-62.3.2-py3-none-any.whl (1.2 MB)
Collecting pyparsing>=2.4.5
  Using cached pyparsing-3.0.9-py3-none-any.whl (98 kB)
Collecting wheel
  Using cached wheel-0.37.1-py2.py3-none-any.whl (35 kB)
Installing collected packages: wheel, setuptools, pyparsing
Successfully installed pyparsing-3.0.9 setuptools-62.3.2 wheel-0.37.1
WARNING: You are using pip version 22.0.4; however, version 22.1 is available.
You should consider upgrading via the '/usr/bin/python3 -m pip install --upgrade pip' command.
/tmp/build-env-7ch4sqe5/lib/python3.9/site-packages/setuptools/config/pyprojecttoml.py:102: _ExperimentalProjectMetadata: Support for project metadata in `pyproject.toml` is still experimental and may be removed (or change) in future releases.
  warnings.warn(msg, _ExperimentalProjectMetadata)
/tmp/build-env-7ch4sqe5/lib/python3.9/site-packages/setuptools/config/_apply_pyprojecttoml.py:194: UserWarning: `install_requires` overwritten in `pyproject.toml` (dependencies)
  warnings.warn(msg)
running sdist
running egg_info
writing bind9_parser.egg-info/PKG-INFO
writing dependency_links to bind9_parser.egg-info/dependency_links.txt
writing requirements to bind9_parser.egg-info/requires.txt
writing top-level names to bind9_parser.egg-info/top_level.txt
reading manifest file 'bind9_parser.egg-info/SOURCES.txt'
reading manifest template 'MANIFEST.in'
warning: no files found matching 'examples/*.conf'
warning: no files found matching 'tests/split-horizon-2-bind9-servers' under directory 'tests'
adding license file 'LICENSE'
writing manifest file 'bind9_parser.egg-info/SOURCES.txt'
running check
creating bind9_parser-0.9.10.1
creating bind9_parser-0.9.10.1/bind9_parser
creating bind9_parser-0.9.10.1/bind9_parser.egg-info
creating bind9_parser-0.9.10.1/docs
creating bind9_parser-0.9.10.1/examples
copying files to bind9_parser-0.9.10.1...
copying ARCHITECTURE.txt -> bind9_parser-0.9.10.1
copying CHANGES -> bind9_parser-0.9.10.1
copying DESIGN.txt -> bind9_parser-0.9.10.1
copying LICENSE -> bind9_parser-0.9.10.1
copying MANIFEST.in -> bind9_parser-0.9.10.1
copying README.md -> bind9_parser-0.9.10.1
copying TODO -> bind9_parser-0.9.10.1
copying pyproject.toml -> bind9_parser-0.9.10.1
copying requirements.txt -> bind9_parser-0.9.10.1
copying setup.cfg -> bind9_parser-0.9.10.1
copying setup.py -> bind9_parser-0.9.10.1
copying tox.ini -> bind9_parser-0.9.10.1
copying bind9_parser/__init__.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_acl.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_aml.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_acl.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_controls.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_dlz.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_dnssec_policy.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_dyndb.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_http.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_key.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_logging.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_managed_keys.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_options.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_parental_agents.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_plugin.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_primaries.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_server.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_statistics_channels.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_tls.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_trust_anchors.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_trusted_keys.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_view.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clause_zone.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_clauses.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_domain.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_inet.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_managed_keys.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_options.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_optview.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_optviewserver.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_optviewzone.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_optviewzoneserver.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_optzone.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_rr.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_server.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_trusted_keys.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_utils.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_view.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_viewzone.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser/isc_zone.py -> bind9_parser-0.9.10.1/bind9_parser
copying bind9_parser.egg-info/PKG-INFO -> bind9_parser-0.9.10.1/bind9_parser.egg-info
copying bind9_parser.egg-info/SOURCES.txt -> bind9_parser-0.9.10.1/bind9_parser.egg-info
copying bind9_parser.egg-info/dependency_links.txt -> bind9_parser-0.9.10.1/bind9_parser.egg-info
copying bind9_parser.egg-info/requires.txt -> bind9_parser-0.9.10.1/bind9_parser.egg-info
copying bind9_parser.egg-info/top_level.txt -> bind9_parser-0.9.10.1/bind9_parser.egg-info
copying docs/README -> bind9_parser-0.9.10.1/docs
copying examples/README -> bind9_parser-0.9.10.1/examples
copying examples/exclamation.py -> bind9_parser-0.9.10.1/examples
copying examples/flatten_namedconf.py -> bind9_parser-0.9.10.1/examples
copying examples/isc_boolean.py -> bind9_parser-0.9.10.1/examples
copying examples/parse_bind9.py -> bind9_parser-0.9.10.1/examples
copying examples/try-me.sh -> bind9_parser-0.9.10.1/examples
Writing bind9_parser-0.9.10.1/setup.cfg
Creating tar archive
removing 'bind9_parser-0.9.10.1' (and everything under it)
/tmp/build-env-7ch4sqe5/lib/python3.9/site-packages/setuptools/config/pyprojecttoml.py:102: _ExperimentalProjectMetadata: Support for project metadata in `pyproject.toml` is still experimental and may be removed (or change) in future releases.
  warnings.warn(msg, _ExperimentalProjectMetadata)
/tmp/build-env-7ch4sqe5/lib/python3.9/site-packages/setuptools/config/_apply_pyprojecttoml.py:194: UserWarning: `install_requires` overwritten in `pyproject.toml` (dependencies)
  warnings.warn(msg)
running bdist_wheel
running build
running build_py
running egg_info
writing bind9_parser.egg-info/PKG-INFO
writing dependency_links to bind9_parser.egg-info/dependency_links.txt
writing requirements to bind9_parser.egg-info/requires.txt
writing top-level names to bind9_parser.egg-info/top_level.txt
reading manifest file 'bind9_parser.egg-info/SOURCES.txt'
reading manifest template 'MANIFEST.in'
warning: no files found matching 'examples/*.conf'
warning: no files found matching 'tests/split-horizon-2-bind9-servers' under directory 'tests'
adding license file 'LICENSE'
writing manifest file 'bind9_parser.egg-info/SOURCES.txt'
installing to build/bdist.linux-x86_64/wheel
running install
running install_lib
creating build/bdist.linux-x86_64/wheel
creating build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_acl.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_parental_agents.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_optview.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_plugin.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_dnssec_policy.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_trusted_keys.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_view.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_logging.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_managed_keys.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_trust_anchors.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_viewzone.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_inet.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_primaries.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_domain.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_masters.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_controls.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_optviewzoneserver.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_dlz.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_rr.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_aml.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_zone.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_utils.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_optzone.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_managed_keys.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_trusted_keys.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_optviewzone.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_key.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_optviewserver.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_zone.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_acl.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_options.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_view.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_tls.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_server.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_dyndb.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_http.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/__init__.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_options.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clauses.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_clause_statistics_channels.py -> build/bdist.linux-x86_64/wheel/bind9_parser
copying build/lib/bind9_parser/isc_server.py -> build/bdist.linux-x86_64/wheel/bind9_parser
running install_egg_info
Copying bind9_parser.egg-info to build/bdist.linux-x86_64/wheel/bind9_parser-0.9.10.1-py3.9.egg-info
running install_scripts
adding license file "LICENSE" (matched pattern "LICEN[CS]E*")
creating build/bdist.linux-x86_64/wheel/bind9_parser-0.9.10.1.dist-info/WHEEL
creating '/home/wolfe/work/github/bind9_parser/dist/tmpve5esfw4/bind9_parser-0.9.10.1-py3-none-any.whl' and adding 'build/bdist.linux-x86_64/wheel' to it
adding 'bind9_parser/__init__.py'
adding 'bind9_parser/isc_acl.py'
adding 'bind9_parser/isc_aml.py'
adding 'bind9_parser/isc_clause_acl.py'
adding 'bind9_parser/isc_clause_controls.py'
adding 'bind9_parser/isc_clause_dlz.py'
adding 'bind9_parser/isc_clause_dnssec_policy.py'
adding 'bind9_parser/isc_clause_dyndb.py'
adding 'bind9_parser/isc_clause_http.py'
adding 'bind9_parser/isc_clause_key.py'
adding 'bind9_parser/isc_clause_logging.py'
adding 'bind9_parser/isc_clause_managed_keys.py'
adding 'bind9_parser/isc_clause_masters.py'
adding 'bind9_parser/isc_clause_options.py'
adding 'bind9_parser/isc_clause_parental_agents.py'
adding 'bind9_parser/isc_clause_plugin.py'
adding 'bind9_parser/isc_clause_primaries.py'
adding 'bind9_parser/isc_clause_server.py'
adding 'bind9_parser/isc_clause_statistics_channels.py'
adding 'bind9_parser/isc_clause_tls.py'
adding 'bind9_parser/isc_clause_trust_anchors.py'
adding 'bind9_parser/isc_clause_trusted_keys.py'
adding 'bind9_parser/isc_clause_view.py'
adding 'bind9_parser/isc_clause_zone.py'
adding 'bind9_parser/isc_clauses.py'
adding 'bind9_parser/isc_domain.py'
adding 'bind9_parser/isc_inet.py'
adding 'bind9_parser/isc_managed_keys.py'
adding 'bind9_parser/isc_options.py'
adding 'bind9_parser/isc_optview.py'
adding 'bind9_parser/isc_optviewserver.py'
adding 'bind9_parser/isc_optviewzone.py'
adding 'bind9_parser/isc_optviewzoneserver.py'
adding 'bind9_parser/isc_optzone.py'
adding 'bind9_parser/isc_rr.py'
adding 'bind9_parser/isc_server.py'
adding 'bind9_parser/isc_trusted_keys.py'
adding 'bind9_parser/isc_utils.py'
adding 'bind9_parser/isc_view.py'
adding 'bind9_parser/isc_viewzone.py'
adding 'bind9_parser/isc_zone.py'
adding 'bind9_parser-0.9.10.1.dist-info/LICENSE'
adding 'bind9_parser-0.9.10.1.dist-info/METADATA'
adding 'bind9_parser-0.9.10.1.dist-info/WHEEL'
adding 'bind9_parser-0.9.10.1.dist-info/top_level.txt'
adding 'bind9_parser-0.9.10.1.dist-info/RECORD'
removing build/bdist.linux-x86_64/wheel
```

Examine the build output files:
```shell
cd build
ls -ltR
```
lists the following build
```console
drwxr-xr-x  3 user user 4096 May 19 21:12 lib

./lib:
drwxr-xr-x 2 user user 4096 May 21 14:30 bind9_parser

./lib/bind9_parser:
drwxr-xr-x 2 user user  4096 May 21 14:30 .
-rw-r--r-- 1 user user  3269 May 21 14:30 __init__.py
-rw-r--r-- 1 user user  1558 May 21 14:20 isc_clause_trusted_keys.py
-rw-r--r-- 1 user user  3526 May 21 13:45 isc_trusted_keys.py
-rw-r--r-- 1 user user  1881 May 21 13:34 isc_view.py
-rw-r--r-- 1 user user  4057 May 21 12:52 isc_clause_trust_anchors.py
-rw-r--r-- 1 user user 27717 May 21 11:35 isc_utils.py
-rw-r--r-- 1 user user  3749 May 21 11:06 isc_clauses.py
-rw-r--r-- 1 user user  4541 May 21 09:46 isc_clause_tls.py
-rw-r--r-- 1 user user 12193 May 21 09:25 isc_zone.py
-rw-r--r-- 1 user user  1984 May 20 18:52 isc_clause_statistics_channels.py
-rw-r--r-- 1 user user  1409 May 20 18:00 isc_clause_plugin.py
-rw-r--r-- 1 user user  2744 May 20 16:28 isc_clause_parental_agents.py
-rw-r--r-- 1 user user 12820 May 20 15:34 isc_inet.py
-rw-r--r-- 1 user user  2823 May 20 15:09 isc_optviewzoneserver.py
-rw-r--r-- 1 user user  3495 May 20 15:08 isc_clause_masters.py
-rw-r--r-- 1 user user  3570 May 20 15:08 isc_clause_primaries.py
-rw-r--r-- 1 user user  2234 May 20 14:39 isc_clause_http.py
-rw-r--r-- 1 user user  6230 May 20 13:36 isc_clause_dnssec_policy.py
-rw-r--r-- 1 user user 13330 May 19 22:51 isc_optviewzone.py
-rw-r--r-- 1 user user  2248 May 19 22:01 isc_clause_acl.py
drwxr-xr-x 3 user user  4096 May 19 21:12 ..
-rw-r--r-- 1 user user  1761 May 19 15:41 isc_clause_view.py
-rw-r--r-- 1 user user  1440 May 19 15:15 isc_clause_zone.py
-rw-r--r-- 1 user user  3929 Feb 22 12:02 isc_acl.py
-rw-r--r-- 1 user user  2713 Feb 22 12:02 isc_aml.py
-rw-r--r-- 1 user user  3431 Feb 22 12:02 isc_clause_controls.py
-rw-r--r-- 1 user user  1318 Feb 22 12:02 isc_clause_dlz.py
-rw-r--r-- 1 user user  1143 Feb 22 12:02 isc_clause_dyndb.py
-rw-r--r-- 1 user user  1552 Feb 22 12:02 isc_clause_key.py
-rw-r--r-- 1 user user  6109 Feb 22 12:02 isc_clause_logging.py
-rw-r--r-- 1 user user   808 Feb 22 12:02 isc_clause_managed_keys.py
-rw-r--r-- 1 user user  2168 Feb 22 12:02 isc_clause_options.py
-rw-r--r-- 1 user user  1420 Feb 22 12:02 isc_clause_server.py
-rw-r--r-- 1 user user  9611 Feb 22 12:02 isc_domain.py
-rw-r--r-- 1 user user  3075 Feb 22 12:02 isc_managed_keys.py
-rw-r--r-- 1 user user 17309 Feb 22 12:02 isc_options.py
-rw-r--r-- 1 user user 22201 Feb 22 12:02 isc_optview.py
-rw-r--r-- 1 user user  1550 Feb 22 12:02 isc_optviewserver.py
-rw-r--r-- 1 user user   693 Feb 22 12:02 isc_optzone.py
-rw-r--r-- 1 user user  3641 Feb 22 12:02 isc_rr.py
-rw-r--r-- 1 user user  7258 Feb 22 12:02 isc_server.py
-rw-r--r-- 1 user user  1115 Feb 22 12:02 isc_viewzone.py
```

And find your distribution compressed tarball file:

```shell
cd ../dist
ls
```
And see your distribution file:
```console
$ ls
bind9_parser-0.9.10.1-py3.9.egg         bind9_parser-0.9.8.1-py3-none-any.whl
bind9_parser-0.9.10.1-py3-none-any.whl  bind9_parser-0.9.8.1.tar.gz
bind9_parser-0.9.10.1.tar.gz
```
