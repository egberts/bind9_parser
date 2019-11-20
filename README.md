bind9-parser reads ISC config files and produces a (massive) Pythonized
Dict/List containing all of its configuration settings.

ISC config files are used in ISC Bind9 server, as well as both
ISC DHCP server and client.

Features:
    - 'include' statements are also supported (my favorite)
    - Relative directory support (not stuck on /etc/bind or /var/lib/bind)
        - Useful for testing many config files in their respective
          local subdirectory(s).
    - Support for Bind 4.8 to v9.15.1 (working on Bind10)

bind9-parser make it so easy to do all of that, and now easier for you.

An example Bind9 config file that contains:

    options {
        version "4.1";
        recursion no;
    }

Result would be:

    result = { 'options': { 'version': "4.1", 'recursion': 'no' }}



== Unit Tests ==
A massive unit test is supplied to ensure that breakage does not occur.

