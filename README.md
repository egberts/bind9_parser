# bind9-parser

You got `named.conf`?  Itching to read it and work with it ... in Python?

Now we can parse `named.conf` with relative ease using Python.  Could even output this as JSON so ANY language can read `named.conf`.

[PyParsing](https://github.com/pyparsing/pyparsing) is our friend, and there are some 2,400 BNF syntax elements for `named.conf` ... in Python3!

# Features

* Pythonized `named.conf` settings
* JSON output
* Schema lookup
* offline local search engine on all Bind9 clauses, statements, and keywords.


# Quick Demo

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
* 'include' statements are also folded into the parser
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



# Unit Tests
A massive unit tests files are supplied (under `tests/` subdirectory) to ensure that future breakage does not occur.

I use JetBrain PyCharm to unittest these all these modules.  However, you can also do it from a command line:
```console
python3 -munittest tests/test_*.py
```

# JSON 

```console
$ ./dump-named-conf-json.py examples/named-conf/named-oracle.conf 
```

```console
print(result.asDict()):
{'logging': [{'category_group': [{'categories': ['default_syslog'],
                                  'category_group_name': 'queries'}]}],
 'options': [{'allow_transfer': {'aml': [{'ip4_addr': '127.0.1.1',
                                          'prefix': '24'}]},
              'datasize': [2098],
              'directory': '/var/named',
              'forward': 'only',
              'forwarders': {'forwarder': [{'ip_addr': '99.11.33.44'}]},
              'recursion': 'no',
              'transfers_in': 10,
              'transfers_per_ns': 2}],
 'zones': [{'file': 'db.cities.zn',
            'type': 'master',
            'zone_name': 'cities.zn'},
           {'file': 'db.127.cities.zn',
            'type': 'master',
            'zone_name': '0.0.127.in-addr.arpa'},
           {'file': 'db.cities.zn.rev',
            'type': 'master',
            'zone_name': '168.192.in-addr.arpa'},
           {'file': 'slave/db.sales.doc',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': 'sales.doc.com'},
           {'file': 'slave/db.sales.doc.rev',
            'masters_zone': {'zone_master_list': [{'ip4': '192.168.1.151'}]},
            'type': 'slave',
            'zone_name': '168.192.in-addr.arpa'}]}

JSON dump:

json-pretty:  {
    "options": [
        {
            "directory": "/var/named",
            "datasize": [
                2098
            ],
            "forward": "only",
            "forwarders": {
                "forwarder": [
                    {
                        "ip_addr": "99.11.33.44"
                    }
                ]
            },
            "recursion": "no",
            "transfers_in": 10,
            "transfers_per_ns": 2,
            "allow_transfer": {
                "aml": [
                    {
                        "ip4_addr": "127.0.1.1",
                        "prefix": "24"
                    }
                ]
            }
        }
    ],
    "logging": [
        {
            "category_group": [
                {
                    "category_group_name": "queries",
                    "categories": [
                        "default_syslog"
                    ]
                }
            ]
        }
    ],
    "zones": [
        {
            "zone_name": "cities.zn",
            "type": "master",
            "file": "db.cities.zn"
        },
        {
            "zone_name": "0.0.127.in-addr.arpa",
            "type": "master",
            "file": "db.127.cities.zn"
        },
        {
            "zone_name": "168.192.in-addr.arpa",
            "type": "master",
            "file": "db.cities.zn.rev"
        },
        {
            "zone_name": "sales.doc.com",
            "type": "slave",
            "file": "slave/db.sales.doc",
            "masters_zone": {
                "zone_master_list": [
                    {
                        "ip4": "192.168.1.151"
                    }
                ]
            }
        },
        {
            "zone_name": "168.192.in-addr.arpa",
            "type": "slave",
            "file": "slave/db.sales.doc.rev",
            "masters_zone": {
                "zone_master_list": [
                    {
                        "ip4": "192.168.1.151"
                    }
                ]
            }
        }
    ]
}
end of result.
```
# Status

At the moment, my focus is on the remaining breakage of just the unittesting scripts for  top-level 'options' clause where I'm busy doing unit-testing, but the EBNF is largely deployed and ready
to go and should work for a large percentage of deployed `named.conf`. It takes time to validate each clause and statement.

In the future, I do expect some minor tweaks for conversion to integer from strings, perhaps some argument validation.  Might be some forgotten aspect of EBNF like (1:N, or 1:1, or even 1:*).

Enjoy the parser.

# Why Did I Do This?

I see lots of Python scripts for ISC Bind Zone files, but not its configuration.  This Bind9 Parser (in Python) has to do or at least pave the way for the following:

* verification of settings against actual environment setting
* security audit
* massive unit testing of Bind 9 using pre-canned configurations
* implement CISecurity against Bind 9 

Closest cousin of Bind configuration format is NGINX config.

Closest Python (and configuration file) parser that I could find was
[liuyangc3/nginx_config_parser](https://github.com/liuyangc3/nginx_config_parser) on GitHub here.

Lots of generator, beautifier, lint, builder, change detector for Bind9 everywhere, but not a Python parser for Bind9 configuration file.

Works for Bind 4.9 to latest v9.19.1.

# Bonus Tool

## Offline Search Engine

Also, I provide a tool to help find related clauses or statements or even keywords related to your specific topic.  

Take **ANSWER** as a topic, let us search for this keyword, oh in Bind9 version 9.8 (kinda old, uh, but it goes up to ***v9.19.1*** **!!!**:

```console
$ python3 examples/rough-draft/namedconfglobal.py  -w topic -k answer -v9.19.1
Version: 9.19.1
Pattern: answer
----------------
sortlist
      comment:
 
The response to a DNS query may consist of multiple resource records
(RRs) forming a resource record set (RRset). The name server
normally returns the RRs within the RRset in an indeterminate order (but
see the ``rrset-order`` statement in :ref:`rrset_ordering`). The client resolver code should
rearrange the RRs as appropriate: that is, using any addresses on the
local net in preference to other addresses. However, not all resolvers
can do this or are correctly configured. When a client is using a local
server, the sorting can be performed in the server, based on the
client's address. This only requires configuring the name servers, not
all the clients.

The ``sortlist`` statement (see below) takes an ``address_match_list`` and
interprets it in a special way. Each top-level statement in the ``sortlist``
must itself be an explicit ``address_match_list`` with one or two elements. The
first element (which may be an IP address, an IP prefix, an ACL name, or a nested
``address_match_list``) of each top-level list is checked against the source
address of the query until a match is found. When the addresses in the first
element overlap, the first rule to match is selected.

Once the source address of the query has been matched, if the top-level
statement contains only one element, the actual primitive element that
matched the source address is used to select the address in the response
to move to the beginning of the response. If the statement is a list of
two elements, then the second element is interpreted as a topology
preference list. Each top-level element is assigned a distance, and the
address in the response with the minimum distance is moved to the
beginning of the response.

In the following example, any queries received from any of the addresses
of the host itself get responses preferring addresses on any of the
locally connected networks. Next most preferred are addresses on the
192.168.1/24 network, and after that either the 192.168.2/24 or
192.168.3/24 network, with no preference shown between these two
networks. Queries received from a host on the 192.168.1/24 network
prefer other addresses on that network to the 192.168.2/24 and
192.168.3/24 networks. Queries received from a host on the 192.168.4/24
or the 192.168.5/24 network only prefer other addresses on their
directly connected networks.


----------------
stale-answer-enable
      comment:
 
If ``yes``, enable the returning of "stale" cached answers when the name
servers for a zone are not answering and the ``stale-cache-enable`` option is
also enabled. The default is not to return stale answers.

Stale answers can also be enabled or disabled at runtime via
:option:`rndc serve-stale on <rndc serve-stale>` or :option:`rndc serve-stale off <rndc serve-stale>`; these override 
the configured setting. :option:`rndc serve-stale reset <rndc serve-stale>` restores the
setting to the one specified in :iscman:`named.conf`. Note that if stale
answers have been disabled by :iscman:`rndc`, they cannot be
re-enabled by reloading or reconfiguring :iscman:`named`; they must be
re-enabled with :option:`rndc serve-stale on <rndc serve-stale>`, or the server must be
restarted.

Information about stale answers is logged under the ``serve-stale``
log category.


----------------
stale-answer-ttl
      comment:
 
This specifies the TTL to be returned on stale answers. The default is 30
seconds. The minimum allowed is 1 second; a value of 0 is updated silently
to 1 second.

For stale answers to be returned, they must be enabled, either in the
configuration file using ``stale-answer-enable`` or via
:option:`rndc serve-stale on <rndc serve-stale>`.


END
```

# Coverages
[![build status](https://api.travis-ci.org/egberts/bind9_parser.svg)](https://travis-ci.org/egberts/bind9_parser)
[![coverage status](https://coveralls.io/repos/github/egberts/bind9_parser/badge.svg)](https://coveralls.io/github/egberts/bind9_parser)  
|  |license| |[![GitHub version](https://badge.fury.io/gh/egberts%2Fbind9_parser.svg)](https://badge.fury.io/gh/egberts%2Fbind9_parser)| |status|
|  |ci-status| |win-ci-status| |docs| | [![codecov](https://codecov.io/gh/egberts/bind9_parser/branch/master/graph/badge.svg?token=V8RieceAFx)](https://codecov.io/gh/egberts/bind9_parser) |
[![star this repo](http://githubbadges.com/star.svg?user=egberts&repo=bind9_parser)](http://github.com/egberts/bind9_parser/star)
[![fork this repo](http://githubbadges.com/fork.svg?user=egberts&repo=bind9_parser)](http://github.com/egberts/bind9_parser/fork)
|  |kit| |format| |repos| |downloads|
|| |contributors|
|  |tidelift| |twitter-coveragepy| |twitter-nedbat|
