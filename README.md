bind9-parser reads ISC config files and produces a (massive) Pythonized
Dict/List containing all of its configuration settings.

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

An example Bind9 config file that contains:
```
    options {
        version "4.1";
        recursion no;
    }
```
bind9-parser result is:
```
    result = { 'options': { 'version': "4.1", 'recursion': 'no' }}
```

# Unit Tests
A massive unit test is supplied (under `tests/` subdirectory) to ensure that future breakage does not occur.

# Others

|Build Status| |Coverage|
