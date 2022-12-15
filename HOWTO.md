
# bind9\_parser HOWTO 

Simplest way to use `bind_parser` is to run 
`dump-named-conf.py` Python script against
my copy of `named.conf`.

## Examples

### Outputting in Python dictionary/list Format

```python
    $ dump-named-conf.py examples/named-conf/basic/named.conf

    print(result.asDict()):
    {'options': [{'directory': '/tmp',
                  'forwarders': {'forwarder': [{'ip_addr': '10.0.0.1'}]},
                  'notify': 'no'}],
     'zones': [{'class': 'in',
                'file': 'localhost.zone',
                'type': 'master',
                'zone_name': 'localhost'},
               {'class': 'in',
                'file': '127.0.0.zone',
                'type': 'master',
                'zone_name': '0.0.127.in-addr.arpa'},
               {'class': 'in',
                'file': 'root.hint',
                'type': 'hint',
                'zone_name': '.'}]}
    end of result.
```

### Outputting in JSON Format

```json
    $ dump-named-conf-json.py examples/named-conf/basic/named.conf
    <snipped output of Python dict/list>
    json-pretty:  {
        "options": [
            {
                "directory": "/tmp",
                "forwarders": {
                    "forwarder": [
                        {
                            "ip_addr": "10.0.0.1"
                        }
                    ]
                },
                "notify": "no"
            }
        ],
        "zones": [
            {
                "zone_name": "localhost",
                "class": "in",
                "type": "master",
                "file": "localhost.zone"
            },
            {
                "zone_name": "0.0.127.in-addr.arpa",
                "class": "in",
                "type": "master",
                "file": "127.0.0.zone"
            },
            {
                "zone_name": ".",
                "class": "in",
                "type": "hint",
                "file": "root.hint"
            }
        ]
    }
    end of result.
```

## Original `named.conf` File

All results above are derived from using this
`examples/named-conf/basic/named.conf` file:

```nginx
options { 
        directory "/tmp";
        forwarders { 10.0.0.1; };
        notify no;
};

zone "localhost" in {
       type master;
       file "localhost.zone";
};

zone "0.0.127.in-addr.arpa" in {
        type master;
        file "127.0.0.zone";
};

zone "." in {
        type hint;
        file "root.hint";
};
'''
