# bind9-parser

I needed a parser for `named.conf` (ISC Bind configuration file) ... in Python.

It has to be able to output a pythonized variable of all settings found in `named.conf`, up to version 9.19.1.

# Quick, Show It To Me

What does the Python variable name look like if I parsed [`named-zytrax.conf`](https://github.com/egberts/bind9_parser/blob/master/examples/named-conf/named-zytrax.conf).

```command
$ ./dump-named-conf.py examples/named-conf/named-zytrax.conf
```

```python
print(result.asDict()):
{'logging': [{'channel': [{'channel_name': 'example_log',
                           'path_name': '/var/log/named/example.log',
                           'print_category': 'yes',
                           'print_severity': 'yes',
                           'print_time': 'yes',
                           'severity': ['info'],
                           'size_spec': [2,
                                         'm'],
                           'versions': 3}]},
             {'category_group': [{'categories': ['example_log'],
                                  'category_group_name': 'default'}]}],
 'options': [{'allow-recursion': {'aml': [{'ip4_addr': '192.168.3.0',
                                           'prefix': '24'}]},
              'allow_transfer': {'aml': [{'acl_name': '"none"'}]},
              'directory': '/var/named',
              'version_string': 'get '
                                'lost'}],
 'zones': [{'file': 'root.servers',
            'type': 'hint',
            'zone_name': '.'},
           {'allow_transfer': {'aml': [{'ip4_addr': '192.168.23.1'},
                                       {'ip4_addr': '192.168.23.2'}]},
            'class': 'in',
            'file': 'master/master.example.com',
            'type': 'master',
            'zone_name': 'example.com'},
           {'allow_update': {'aml': [{'keyword': 'none'}]},
            'class': 'in',
            'file': 'master.localhost',
            'type': 'master',
            'zone_name': 'localhost'},
           {'allow_update': {'aml': [{'keyword': 'none'}]},
            'class': 'in',
            'file': 'localhost.rev',
            'type': 'master',
            'zone_name': '0.0.127.in-addr.arpa'},
           {'class': 'in',
            'file': '192.168.0.rev',
            'type': 'master',
            'zone_name': '0.168.192.IN-ADDR.ARPA'}]}
```

# Why Did I Do This?

I see lots of Python scripts for ISC Bind Zone files, but not its configuration.  This Bind9 Parser (in Python) has to do the following:

* verification of settings against actual environment setting
* security audit
* massive unit testing of Bind 9 using pre-canned configurations
* implement CISecurity against Bind 9 

Closest cousin of Bind configuration format is NGINX config.

Closest Python (and configuration file) parser that I could find was
[liuyangc3/nginx_config_parser](https://github.com/liuyangc3/nginx_config_parser) on GitHub here.

Lots of generator, beautifier, lint, builder, change detector for Bind9 everywhere, but not a Python parser for Bind9 configuration file.

Works for Bind 4.9 to latest v9.19.1.


# Quick HOWTO

To take your `named.conf` file and output a Pythonized variable containing ALL
of the settings found:

```shell
./dump-named-conf.py examples/named-conf/named-oracle.conf
```
and the output of the Python array variable is:
```console
{'logging': [{'category_group': [{'categories': ['default_syslog'],
                                  'category_group_name': 'queries'}]}],
 'options': [{'allow_transfer': {'aml': [{'addr': '127.0.1.1/24'}]},
              'datasize': [2098],
              'directory': '"/var/named"',
              'forward': 'only',
              'forwarders': {'forwarders_list': [{'addr': '99.11.33.44'}]},
              'recursion': 'no',
              'transfers_in': 10,
              'transfers_per_ns': 2}],
 'zones': [{'file': '"db.cities.zn"',
            'type': 'master',
            'zone_name': '"cities.zn"'},
           {'file': '"db.127.cities.zn"',
            'type': 'master',
            'zone_name': '"0.0.127.in-addr.arpa"'},
           {'file': '"db.cities.zn.rev"',
            'type': 'master',
            'zone_name': '"168.192.in-addr.arpa"'},
           {'file': '"slave/db.sales.doc"',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': '"sales.doc.com"'},
           {'file': '"slave/db.sales.doc.rev"',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': '"168.192.in-addr.arpa"'}]}
```

To install this package, consult README.install.md


# Features

Features:
* 'include' statements are also supported (my favorite)
* Relative directory support (not stuck on /etc/bind or /var/lib/bind)
  * Useful for testing many config files in their respective local subdirectory(s).
* Support for Bind 4.8 to v9.15.1 (working on Bind10)
* ISC config files are used in ISC Bind9 server, as well as both ISC DHCP server and client.

bind9-parser make it so easy to do all of that, and now easier for you.

# Introduction
Here is a program to parse ``"options { server-id 'example.invalid'; };"`` :

```python

    from bind9_parser import *
    test_named_conf_text = "options { server-id 'example.invalid'; };"
    result = clause_statements.parseString(test_named_conf_text, parseAll=True)
    print(result.asDict())
```

The program outputs the following::

```python
    {'options': [{'server_id_name': "'example.invalid'"}]}
```

# Parse Everthing here
One issue #10 asked to provide an example to parse the whole named.conf thing.

We start with the supplied `named.conf` below:
```nginx
view "trusted" {

match-clients { 192.168.23.0/24; };
recursion yes;
zone "example.com" {
type master;
file "internal/master.example.com";
};
zone "example22.com" {
type master;
file "internal/master.example22.com";
};
};
view "badguys" {
match-clients {"any"; };
recursion no;
zone "exampleaa.com" {
type master;
file "external/master.exampleaa.com";
};
};

```
I didn't reformat it.  But the following snippet of bash execution will 
parse it just fine:
```bash
cd bind9_parser/examples
python3 dump-named-conf.py ./tests/bug-reports/github-issue-10.named.conf
```
To obtain a Python list variable, the same `parse_bind9.py` will get you this output:
```python
[['"trusted"',
  [[['192.168.23.0/24']],
   'yes',
   ['"example.com"', 'master', '"internal/master.example.com"'],
   ['"example22.com"', 'master', '"internal/master.example22.com"']]],
 ['"badguys"',
  [[['"any"']],
   'no',
   ['"exampleaa.com"', 'master', '"external/master.exampleaa.com"']]]]
result: {'view': [{'view_name': '"badguys"', 'configs': {'match_clients': {'aml': [{'acl_name': '"any"'}]}, 'recursion': 'no', 'zone': {'zone_name': '"exampleaa.com"', 'type': 'master', 'file': '"external/master.exampleaa.com"'}}}]}
```
To obtain a Python dictionary variable, again the same `bind9_parser.py` will get you this result:
```python
print(result.asDict()):
{ 'view': [ {
    'configs': {
        'match_clients': {
            'aml': [ {
                'acl_name': '"any"'}]},
        'recursion': 'no',
        'zone': {
            'file': '"external/master.exampleaa.com"',
            'type': 'master',
            'zone_name': '"exampleaa.com"'}},
    'view_name': '"badguys"'}]}
```

I hope this helps.

# Unit Tests
A massive unit tests files are supplied (under `tests/` subdirectory) to ensure that future breakage does not occur.

I use JetBrain PyCharm to unittest these modules.  However, you can also do it from a command line:
```console
python3 -munittest tests/test_*.py
```

# Status

At the moment, my focus is on the remaining breakage of just the unittesting scripts for  top-level 'options' clause where I'm busy doing unit-testing, but the EBNF is largely deployed and ready
to go and should work for a large percentage of deployed `named.conf`. It takes time to validate each clause and statement.

In the future, I do expect some minor tweaks for conversion to integer from strings, perhaps some argument validation.  Might be some forgotten aspect of EBNF like (1:N, or 1:1, or even 1:*).

Enjoy the parser.


# Coverages
* [![Coverage Status (master)](https://coveralls.io/repos/github/egberts/bind9_parser/badge.svg?branch=master)](https://coveralls.io/github/egberts/bind9_parser?branch=master)
|  |license| |versions| |status|
|  |ci-status| |win-ci-status| |docs| |codecov|
|  |kit| |format| |repos| |downloads|
|  |stars| |forks| |contributors|
|  |tidelift| |twitter-coveragepy| |twitter-nedbat|
