bind9-parser reads ISC config files and produces a (massive) Pythonized
Dict/List containing all of its configuration settings.

# **BETA RELEASE - BETA RELEASE - BETA RELEASE**

# bind9-parser

I needed a parser in Python that can handle ISC Bind configuration file.

# Why Did I Do This?

I see lots of Python scripts for ISC Bind Zone files, but not its configuration.

The closest cousin of Bind configuration format is NGINX config.

The closest Python (and configuration file parser) I could find was
[liuyangc3/nginx_config_parser](https://github.com/liuyangc3/nginx_config_parser) on GitHub here.

On GitHub, I have found lots of generator, beautifier, lint, builder, change detector for Bind9, but no really good parser for Bind9 configuration file.

I built a complete parser that will work on version 4.9 to 9.15.  Why did I name
it Bind9-parser?  Because I started out only to cover Bind version 9.0 to 9.15.
I later expanded it to cover 4.9 on up.

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

.. code:: python

    from bind9_parser import *
    test_named_conf_text = "options { server-id 'example.invalid'; };"
    result = clause_statements.parseString(test_named_conf_text, parseAll=True)
    print(result.asDict())

The program outputs the following::

    {'options': [{'server_id_name': "'example.invalid'"}]}

# Parse Everthing here
One issue #11 asked to provide an example to parse the whole named.conf thing.

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
python3 parse_bind.py /tmp/github-issue-10.named.conf
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
A massive unit test is supplied (under `tests/` subdirectory) to ensure that future breakage does not occur.

# Others


# Coverages
* [![Coverage Status (master)](https://coveralls.io/repos/github/egberts/bind9_parser/badge.svg?branch=master)](https://coveralls.io/github/egberts/bind9_parser?branch=master)
|  |license| |versions| |status|
|  |ci-status| |win-ci-status| |docs| |codecov|
|  |kit| |format| |repos| |downloads|
|  |stars| |forks| |contributors|
|  |tidelift| |twitter-coveragepy| |twitter-nedbat|
