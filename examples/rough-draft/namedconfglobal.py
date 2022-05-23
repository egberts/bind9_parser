"""
#
"""
import re
from pprint import PrettyPrinter
from typing import Dict, Any

# import line_profiler

"""
Bind9 named.conf global settings

Template is:
abc = {
  'required': True, bare minimum keyword
              required within its subblock context
              (as pointed to by its presence
  'default': "yes",   # None, if statement is a
             presence-trigger type; all int() type
             are in str()type
  'default': {1: {'addr': 'any', 'operator_not': False}, },
  'occurs-multiple-times': True,  # This keyword can
                                  # happen more than once
                                  # in a config file
  'validity': { 'range': {0, 4095}, # None, if no validity needed
    'regex': r"(yes|no|[0-9]{1-3})",
    'function': custom_range_checking,   # combination of validity supported
  },
  'found-in': {'options', 'view', 'zone', 'server', 'key'},
  'user-defined-indices': True,  # acl_name_base (useful to skip keyword validation)
  'multi-line-order-id': 1  # determines print order within {}
  'same-line-order-id': 1  # determines print order within same line
  'introduced': '9.5',  # introduced ON that version,
                        # string-format-only, dotted notation
  'deprecated': '',  # keyword remains useable but has diminishing logics
  'obsoleted': '',  # obsoleted ON that version,
                    # presense means immediately obsoleted
  'topic': 'recursive-follow',  # free-format
          'comment': """ """  # Comments are less than 55 columns
    }
"""

# Stuff that goes into subdirectory's namedconfglobal.py
# are defined once at "import namedconf" time.
# We declare these variables as class instance
# variable: loaded once, shared by many class instances.

# g_nc_keywords is a dict() that contains all
# first-order keyword (typically after CR/LF and
# and after the '};' or ';' end-section marker).
# g_nc_keywords is designed for speed of keyword
# lookups, ease of using g_nc_keywords['options']
# access, and does not necessarily reflect ordering
# found in original named.conf configuration file.
#
# To reconstruct its original ordering of the
# output configuration file, we use absolute
# cursor position embedded in self.current['keyword']
# as a reordering guide for this.
global g_nc_keywords
g_nc_keywords = dict()

g_nc_keywords['acl'] = \
    {
        'occurs-multiple-times': True,
        'default': None,
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {''},
        'multi-line-order-id': 1,  # ACL 'should' always be first, but not always, but I say so
        'user-defined-indices': True,  # acl_name_base
        'introduced': "8.1",
        'topblock': True,
        'topic': 'access control list, RPZ rewriting, content filtering',
    }

g_nc_keywords['controls'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {''},
        'output-order-id': 3,  # controls should be prominently firstly (after keys and ACLs)
        'introduced': '8.2',
        'topic': 'RNDC, remote control',
    }

g_nc_keywords['dnssec-keys'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'view'},
        'output-order-id': 11,  # controls should be prominently firstly (after keys and ACLs)
        'default': '',
        'validity': {'function': 'dnskey', },
        'introduced': '9.15.2',
        'obsoleted': '9.15.6',  # arguably the shortest-lived 'clause'
        'topic': 'DNSSEC, key',
        'comment': " ",
    }

#  dlz <string> { database <string>; search <boolean>; }; [ DLZ ]
#  dlz <string>; [ View Zone ]
g_nc_keywords['dlz'] = \
    {
        'default': None,
        'validity': {'function': 'netprefix'},
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'view', 'zone'},  # also at top-statement-level
        'topic': 'dlz, redirect',
        'zone-type': {'master', 'slave', 'redirect', 'primary', 'secondary'},
        'introduced': "9.5.0",
        'comment': """ Introduced 'search' statement in v9.10.0 """,
    }

g_nc_keywords['dnssec-policy'] = \
    {
        # This is one of those split-syntax/same-name between top-level and options
        'default': '',
        'validity': {'function': 'dnssec_policy_name',
                     'regex': '(none|default)'},
        'occurs-multiple-times': True,
        'topblock': True,
        'required': False,  # depends on topblock 'dnssec-policy'
        'found-in': {'', 'options'},
        'introduced': '9.17.0',
        'topic': 'DNSSEC, policy',
        'comment': '',
    }

#  dyndb <string> <quoted_string> { <unspecified-text> };
g_nc_keywords['dyndb'] = \
    {
        'default': '',
        'occurs-multiple-times': True,
        'topblock': True,
        'required': False,
        'found-in': {'', 'view'},  # added to 'view' in v9.11.0
        'introduced': '9.6.0',
        'topic': 'dynamic database',
        'comment': ''
    }

g_nc_keywords['http'] = \
    {
        'default': None,
        'topblock': True,
        'occurs-multiple-times': True,
        'validity': {'string'},
        'found-in': {''},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': '',
    }

g_nc_keywords['include'] = \
    {
        'default': None,
        'validity': {'function': 'path_name'},
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'options', 'view', 'zone', 'server', 'masters', 'key'},
        'introduced': '8.1',
        'topic': 'multi-file configuration',
        'comment': 'A placeholder for more configuration items',
    }

g_nc_keywords['key'] = \
    {
        'validity': {'string': 'key_name'},
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'view', 'primaries', 'masters', 'also-notify', 'catalog-zones', 'parental-agents'},
        # found in view since v9.0
        'user-defined-indices': True,  # keyname
        'multi-line-order-id': 2,  # Keys should always be on top, after ACL
        'topic': 'key',
        'introduced': "8.1",
    }

g_nc_keywords['keys'] = \
    {
        'validity': {'function': 'list_of_strings'},
        'occurs-multiple-times': False,
        'topblock': False,
        'found-in': {'inet', 'unix', 'dnssec-policy', 'server'},
        'multi-line-order-id': 2,  # Keys should always be on top, after ACL
        'topic': 'list of keys',
        'introduced': "9.0",
    }

g_nc_keywords['logging'] = \
    {
        'occurs-multiple-times': False,
        'topblock': True,
        'required': False,
        'found-in': {''},
        'subordering-matters': True,
        'output-order-id': 20,  # 'logging' is second last
        'introduced': "8.1",
        'topic': 'debug, log, logging, log file'
    }

g_nc_keywords['lwres'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {''},
        'dict-index-by-name': False,
        'subordering-matters': False,
        'introduced': "9.1",
        'obsoleted': '9.12.0',
    }

g_nc_keywords['managed-keys'] = \
    {
        'occurs-multiple-times': True,  # was shocked that this is a multiple entry supported clause
        'topblock': False,
        'found-in': {'', 'view'},  # also at top-statement-level
        'introduced': '9.5.0',
        'deprecated': "9.15.1",  # replaced by 'dnssec-keys' w/ 'initial-key'
        'topic': 'DNSSEC, key',
        'comment': '',
    }

# This is top-level 'masters' only which is
# not to be confused with 'zone' 'masters' option.
g_nc_keywords['masters'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'zone'},  # Only found in zone-slave/zone-stub
        'user-defined-indices': True,
        'output-order-id': 8,  # masters should be after 'view'/'zone'
        'topic': 'nameserver, master, server, transfer',
        'introduced': "4.8",
    }

g_nc_keywords['options'] = \
    {
        'occurs-multiple-times': False,
        'topblock': True,
        'required': True,  # the only keyword w/ 'required' (nope, logging too)
        'found-in': {''},
        'output-order-id': 4,  # options should be after keys, ACLs, and controls)
        'topic': 'general options',
        'introduced': "4.9.3"  # 1994 Vixie Enterprise
    }

g_nc_keywords['parental-agents'] = \
    {
        'occurs-multiple-times': False,
        'topblock': True,
        'required': False,
        'found-in': {''},
        'introduced': "9.19",
        'topic': '',
        'comment': '',
    }

g_nc_keywords['plugin'] = \
    {
        'default': None,
        'validity': {'function': 'plugin'},
        'found-in': {'', 'view'},
        'topblock': True,
        'occurs-multiple-times': True,
        'introduced': '9.14.0',
        'topic': 'plugin',
        'comment': '',
    }

g_nc_keywords['primaries'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'zone'},  # Only found in zone-slave/zone-stub
        'user-defined-indices': True,
        'output-order-id': 8,  # masters should be after 'view'/'zone'
        'topic': 'nameserver, server, list of masters, list of servers, transfer',
        'zone-type': {'mirror', 'secondary', 'stub', 'redirect'},
        'introduced': "9.16",
    }

g_nc_keywords['server'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'view'},  # also at top-statement-level
        'dict-index-by-name': True,  # indexed by ip46_addr_or_prefix
        'output-order-id': 9,  # 'server' should be AFTER 'masters'
        'topic': 'view, server',
        'introduced': "8.1",
    }

g_nc_keywords['statistics-channels'] = \
    {
        'occurs-multiple-times': False,
        'topblock': True,
        'found-in': {''},
        'output-order-id': 9999,
        'introduced': '9.5.0',
        'comment': 'statistics, channel',
    }

g_nc_keywords['tls'] = \
    {
        'topblock': True,
        'validity': {'string'},
        'dict-index-by-name': True,
        'found-in': {'', 'primaries', 'masters', 'listen-on', 'listen-on-v6',
                     'parental-agents', 'also-notify', 'catalog-zones'},
        'occurs-multiple-times': True,
        'introduced': '9.18.0',
        'topic': 'TLS, DNS-over-HTTP, DoH',
        'comment': '',
    }

g_nc_keywords['trust-anchors'] = \
    {
        'topblock': True,
        'found-in': {'', 'options', 'view'},
        'dict-index-by-name': False,  # but 'trusted-keys string' is indexed
        'occurs-multiple-times': True,
        'output-order-id': 10,
        'introduced': "9.16",
    }

g_nc_keywords['trusted-keys'] = \
    {
        'topblock': True,
        'found-in': {'', 'view', 'server'},  # Found in 'server' in 9.0
        'dict-index-by-name': False,  # but 'trusted-keys string' is indexed
        'occurs-multiple-times': True,
        'output-order-id': 10,
        'introduced': "8.2",  # 1999-09-15
        'deprecated': "9.15.1",  # replaced by 'dnssec-keys' w/ 'static-key'
        # 'obsoleted': "9.20?",
    }

g_nc_keywords['view'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {''},
        'subordering-matters': True,  # ordering of view is very important
        'user-defined-indices': True,  # view_name
        'output-order-id': 6,  # 'view'/'zone' should be before 'trusted-keys'
        'introduced': "9.0.0",  # A big feature introduction here
        'default': None,
        'validity': {'function': 'view_name'},
        'topic': 'view'
    }

g_nc_keywords['zone'] = \
    {
        'occurs-multiple-times': True,
        'topblock': True,
        'found-in': {'', 'view'},
        'subordering-matters': True,  # ordering of zone is very important
        'user-defined-indices': True,  # zone_name
        'output-order-id': 6,  # 'zone'/'view' should be before 'trusted-keys'
        'introduced': "8.1",
    }

# End of Top-Level Statement (formerly clause)

# Begin of keywords, builtins and identifiers

g_nc_keywords['acache-cleaning-interval'] = \
    {
        'default': "no",
        'validity': {'regex': r'(yes)|(no)'},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'obsoleted': '9.12',
        'topic': 'additional section cache, caching',
        'comment': """If yes, additional section caching is enabled.
The default value is no.""",
    }

g_nc_keywords['acache-enable'] = \
    {
        'default': "no",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'obsoleted': '9.12',
        'topic': 'caching, additional section cache',
        'comment': """If yes, additional section caching is enabled.
The default value is no.""",
    }

g_nc_keywords['additional-from-auth'] = \
    {
        'default': "yes",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.1',
        'obsoleted': '9.12',
        'topic': 'authoritative, non-caching, recursive-follow, caching',
        'comment': """These options control the behavior of an authoritative
server when answering queries which have additional
 when following CNAME and DNAME chains.

When both of these options are set to yes (the default)
and a query is being answered from authoritative data
(a zone configured into the server), the additional
data section of the reply will be filled in using data
from other authoritative zones and from the cache. In
some situations this is undesirable, such as when there
is concern over the correctness of the cache, or in
servers where slave zones may be added and modified by
untrusted third parties. Also, avoiding the search
for this additional data will speed up server
operations at the possible expense of additional
queries to resolve what would otherwise be provided
in the additional section.

For example, if a query asks for an MX record for host
foo.example.com, and the record found is
"MX 10 mail.example.net", normally the address records
(A and AAAA) for mail.example.net will be provided as
well, if known, even though they are not in the
example.com zone. Setting these options to no disables
this behavior and makes the server only search for
additional data in the zone it answers from.

These options are intended for use in
authoritative-only servers, or in authoritative-only
views. Attempts to set them to no without also
specifying recursion no will cause the server to
ignore the options and log a warning message.

Specifying additional-from-cache no actually disables
the use of the cache not only for additional data
lookups but also when looking up the answer. This is
usually the desired behavior in an authoritative-only
server where the correctness of the cached data is an
issue.

When a name server is non-recursively queried for a
name that is not below the apex of any served zone,
it normally answers with an "upwards referral" to the
root servers or the servers of some other known parent
of the query name. Since the data in an upwards
referral comes from the cache, the server will not be
able to provide upwards referrals when
additional-from-cache no has been specified. Instead,
it will respond to such queries with REFUSED. This
should not cause any problems since upwards referrals
are not required for the resolution process.

The default in both cases is yes.

These statements may be used in a global options or in
a view clause.

The behaviour is defined by the table below:
auth    cache   BIND Behaviour
yes     yes     BIND will follow out of zone records e.g. it will
            follow the MX record specifying mail.example.net
            for zone example.com for which it is authoritative
            (master or slave). Default behaviour.
no      no      Cache disabled. BIND will NOT follow out-of-zone
            records even if it is in the cache e.g. it will NOT
            follow the MX record specifying mail.example.net for
            zone example.com for which it is authoritative
            (master or slave). It will return REFUSED for the
            out-of-zone record.
yes     no      Cache disabled. BIND will follow out-of-zone records
            but since this requires the cache (which is disabled)
            the net result is the same - BIND will return REFUSED
            for the out-of-zone record.
no      yes     BIND will NOT follow out-of-zone records but if it is
            the cache it will be returned. If not in the cache
            BIND will return REFUSED for the out-of-zone record.

            Prior to BIND 9.5 auth-from-cache also controlled whether
            a recursive query (even when recursion no; was specified)
            would return a referral to the root servers (since these
            would, most likely, be available in the cache). Since
            BIND 9.5+ such queries are now failed with REFUSED status.""",
    }

g_nc_keywords['additional-from-cache'] = \
    {
        'default': "yes",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.1',
        'obsoleted': '9.12',
        'topic': 'authoritative, non-caching, recursive-follow',
        'comment': """additional-from-auth and additional-from-cache control
the behaviour when zones have additional (out-of-zone)
data or when following CNAME or DNAME records. These
options are for used for configuring authoritative-only
(non-caching) servers and are only effective if
recursion no is specified in a global options clause
or in a view clause.

The default in both cases is yes.

These statements may be used in a global options or
in a view clause.

The behaviour is defined by the table below:
auth    cache   BIND Behaviour
yes     yes     BIND will follow out of zone records e.g. it will
            follow the MX record specifying mail.example.net
            for zone example.com for which it is authoritative
            (master or slave). Default behaviour.
no      no      Cache disabled. BIND will NOT follow out-of-zone
            records even if it is in the cache e.g. it will NOT
            follow the MX record specifying mail.example.net for
            zone example.com for which it is authoritative
            (master or slave). It will return REFUSED for the
            out-of-zone record.
yes     no      Cache disabled. BIND will follow out-of-zone records
            but since this requires the cache (which is disabled)
            the net result is the same BIND will return REFUSED
            for the out-of-zone record.
no      yes     BIND will NOT follow out-of-zone records but if it is
            the cache it will be returned. If not in the cache
            BIND will return REFUSED for the out-of-zone record.

            Prior to BIND 9.5 auth-from-cache also controlled whether
            a recursive query (even when recursion no; was specified)
            would return a referral to the root servers (since these
            would, most likely, be available in the cache). Since
            BIND 9.5+ such queries are now failed with REFUSED status."""
    }

g_nc_keywords['algorithm'] = \
    {
        'default': '',  # insist
        'validity': {'string': 'hmac_algorithm'},
        'occurs-multiple-times': False,
        'topblock': False,
        'found-in': {'key'},  # also at top-statement-level
        'topic': 'algorithm',
        'user-defined-indices': False,
        'multi-line-order-id': 1,  # it's before 'secret' within 'key'
        'introduced': "9.18.0",  #
        'comment': """Valid algorithms are:
   hmac-md5
   hmac-md5.sig-alg.reg.int
   hmac-md5.sig-alg.reg.int.
   hmac-sha1
   hmac-sha224
   hmac-sha256
   hmac-sha384
   hmac-sha512
"""
    }

g_nc_keywords['all-per-seconds'] = \
    {
        'default': None,
        'validity': {'range': {0, 1000}},
        'found-in': {'rate-limit'},
        'introduced': '9.8.0',
        'topic': 'rate-limit, defense',
        'comment': ''
    }

g_nc_keywords['allow-new-zones'] = \
    {
        'default': 'no',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'topic': 'rndc, zone, ddns',
        'comment': """If yes, then zones can be added at runtime via 'rndc addzone', 
'rndc modzone' or deleted via 'rndc delzone'. The default is no.""",
    }

g_nc_keywords['allow-notify'] = \
    {
        'default': {0: {'masters': 'none', 'operator_not': False}, },  # was 'any' in v9.11
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.1',
        'topic': 'access control, recursive-follow',
        'zone-type': {'slave', 'mirror', 'secondary'},
        'comment': """Specifies which hosts are allowed to notify this
server, a slave, of zone changes in addition to the
zone masters. allow-notify may also be specified in
the zone statement, in which case it overrides the
options allow-notify statement. It is only meaningful
for a slave zone.

If not specified, the default is to process notify
messages only from a zones master.
""",
    }

g_nc_keywords['allow-query'] = \
    {
        'default': {0: {'addr': 'any', 'operator_not': False}, },
        'validity': {'function': "address_match_list"},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '8.1',
        # In 8.2, only found in ['zone']['type']['master']
        # In 8.2, only found in ['zone']['type']['slave']
        # In 8.2, only found in ['zone']['type']['stub']
        'topic': 'active, access control, redirect',
        'zone-type': {'active', 'public', 'master', 'slave', 'mirror',
                      'stub', 'static-stub', 'redirect', 'primary', 'secondary'},
        'comment': """Specifies which hosts are allowed to ask ordinary
DNS questions. allow-query may also be specified in the
zone statement, in which case it overrides the options
allow-query statement.

If not specified, the default is to allow queries from
all hosts.

NOTE: allow-query-cache is now used to specify access
to the cache.""",
    }

g_nc_keywords['allow-query-cache'] = \
    {
        'default': {0: {'addr': 'localnets', 'operator_not': False},
                    1: {'addr': 'localhost', 'operator_not': False}, },
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'caching, cache access control',
        'comment': """Specifies which hosts are allowed to get answers from the cache.

If allow-query-cache is not set then allow-recursion is used if set,
otherwise allow-query is used if set unless recursion no; is set
in which case none; is used,
otherwise the default (localnets; localhost;) is used.""",
    }

g_nc_keywords['allow-query-cache-on'] = \
    {
        'default': {0: {'addr': 'any', 'operator_not': False}},
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view'},
        'introduced': '9.5.0',
        'topic': 'caching, cache access control, active',
        'comment': '',
    }

g_nc_keywords['allow-query-on'] = \
    {
        'default': {0: {'addr': 'any', 'operator_not': False}},
        'validity': {'function': 'address_match_list'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.5.0',
        'topic': 'access control, redirect, caching',
        'zone-type': {'master', 'slave', 'mirror', 'stub',
                      'static-stub', 'redirect', 'primary', 'secondary'},
        'comment': """Specifies which local addresses can accept ordinary
DNS questions. This makes it possible, for instance, to
allow queries on internal-facing interfaces but disallow
them on external-facing ones, without necessarily knowing
the internal networks addresses.

Note that allow-query-on is only checked for queries that
are permitted by allow-query.

A query must be allowed by both ACLs, or it will be refused.

allow-query-on may also be specified in the zone
statement, in which case it overrides the options
allow-query-on statement.

If not specified, the default is to allow queries on
all addresses.

NOTE: allow-query-cache is used to specify access
to the cache.""",
    }

g_nc_keywords['allow-recursion'] = \
    {
        'default': {0: {'addr': 'localnets', 'operator_not': False},
                    1: {'addr': 'localhost', 'operator_not': False}, },
        # 'default' was 'any;' in v9.11
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view'},
        'introduced': '9.0.0',
        'topic': 'caching, recursion, access control',
        'comment': """Specifies which local addresses can give answers from
the cache.  If not specified, the default is to allow
cache queries on any address, localnets and localhost.""",
    }

g_nc_keywords['allow-recursion-on'] = \
    {
        'default': {0: {'addr': 'any'}},
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view'},
        'introduced': '9.5.0',
        'topic': 'recursion, local addresses',
        'comment': """Specifies which local addresses can accept
recursive queries.  If not specified, the default is to
allow recursive queries on all addresses."""
    }

g_nc_keywords['allow-transfer'] = \
    {
        'default': {0: {'addr': 'any'}},
        'validity': {
            'port': 'optional',  # added in v9.18
            'transport': 'optional',  # added in v9.18
            'function': 'address_match_list'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '8.1',
        # In 8.2, only found in ['zone']['type']['master']
        # In 8.2, only found in ['zone']['type']['slave']
        # In 8.2, only found in ['zone']['type']['stub']
        'topic': 'server-zone-transfer-permission, access control',
        'zone-type': {'authoritative', 'master', 'slave',
                      'mirror', 'stub', 'primary', 'secondary'},
        'comment': """Specifies which hosts are allowed to receive zone
transfers from the server.  allow-transfer may also be
specified in the zone statement, in which case it
overrides the options allow-transfer statement.

If not specified, the default is to allow transfers to
all hosts.""",
    }

g_nc_keywords['allow-update'] = \
    {
        'default': {0: {'addr': 'none'}},
        'validity': {'function': 'address_match_list'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '8.2',
        # In 8.2, only found in ['zone']['type']['master']
        # In 8.2, not found in ['zone']['type']['slave']
        # In 8.2, not found in ['zone']['type']['stub']
        # In 8.2, not found in ['zone']['type']['forward']
        # In 8.2, not found in ['zone']['type']['hint']
        'topic': 'update, dynamic-dns, dynamic zone, access control',
        'zone-type': {'authoritative', 'master', 'mirror', 'primary'},
        'comment': """Specifies which hosts are allowed to submit Dynamic
DNS updates for master zones.  The default is to deny
updates from all hosts.  Note that allowing updates
based on the requestor's IP address is insecure;"""
    }

g_nc_keywords['allow-update-forwarding'] = \
    {
        'default': {0: {'addr': 'none'}},
        'validity': {'function': 'address_match_list'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.0.0',
        'topic': 'update, dynamic-dns, access control',
        'zone-type': {'secondary', 'mirror', 'slave'},
        'comment': """Specifies which hosts are allowed to submit Dynamic
DNS updates for master zones.

The default is to deny updates from all hosts.

Useful when secondary nameserver receives a DHCP
updates and needs to inform the server having this
master zone file.

Note that allowing updates based on the requestor's IP
address is insecure;"""
    }

g_nc_keywords['allow-v6-synthesis'] = \
    {
        'default': "",
        'validity': {'regex': "(AAAA|A6)"},
        'found-in': {'options', 'view', 'server'},
        'introduced': '9.2',
        'obsoleted': '9.8',
        'topic': 'inert, ignored, obsoleted, IPv6',
        'comment': """This option was introduced for the smooth transition
from AAAA to A6 and from "nibble labels" to binary labels.

However, since both A6 and binary labels were then
deprecated, this option was also deprecated. It is now
ignored with some warning messages.""",
    }

g_nc_keywords['also-notify'] = \
    {
        'default': {},
        'validity': {'function': "ip_addr_list"},
        'found-in': {'options', 'view', 'zone'},
        # In 8.2, only found in ['zone']['type']['master']
        # In 8.2, only found in ['zone']['type']['slave']
        # In 8.2, only found in ['zone']['type']['stub']
        # In 9.15, no longer found under 'server'
        'introduced': '8.2',
        'topic': 'notify, transfer, TSIG, DSCP',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'primary', 'secondary'},
        'comment': """Defines a global list of IP addresses of name
servers that are also sent NOTIFY messages whenever a
fresh copy of the zone is loaded, in addition to the
servers listed in the zone's NS records. This helps to
ensure that copies of the zones will quickly converge on
stealth servers. Optionally, a port may be specified with
each also-notify address to send the notify messages to a
port other than the default of 53. An optional TSIG key
can also be specified with each address to cause the
notify messages to be signed; this can be useful when
sending notifies to multiple views. In place of explicit
addresses, one or more named masters lists can be used.
If an also-notify list is given in a zone statement, it
will override the options also-notify statement. When a
zone notify statement is set to no, the IP addresses in
the global alsonotify list will not be sent NOTIFY
messages for that zone. The default is the empty list
(no global notification list).
'key' directive within 'allow-notify' introduced in v9.9.0.
Master name permitted in v9.9.0. """,
    }

g_nc_keywords['alt-transfer-source'] = \
    {
        'default': '',
        'validity': {'function': 'ip_address_port'},
        'found-in': {'options', 'view'},  # removed 'zones' in v9.10
        'introduced': '9.3.0',
        'topic': 'slave, transfer, DSCP',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment':
            """Applies to slave zones only.  Defines an alternative
            local IP address to be used for inbound zone transfers
            by the server if that defined by transfer-source
            (transfer-source-v6) fails and use-alt-transfer-source
            is enabled.
            
            This address must appear in the remote end's
            allow-transfer statement for the zone being transferred.
            
            Syntax: ( ipv4_address | * ) [ port ( integer | * )];
            
            This statement may be used in a zone, view or global
            options clause."""
    }

g_nc_keywords['alt-transfer-source-v6'] = \
    {
        'default': '',
        'validity': {'function': 'ip_address_port'},
        'found-in': {'options', 'view'},  # removed 'zones' in v9.10
        'introduced': '9.3.0',
        'topic': 'slave, transfer',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},  # removed in v9.10
        'comment':
            """Applies to slave zones only.  Defines an alternative
local IP address to be used for inbound zone transfers
by the server if that defined by transfer-source
(transfer-source-v6) fails and use-alt-transfer-source
is enabled.

This address must appear in the remote end's
allow-transfer statement for the zone being transferred.

This statement may be used in a zone, view or global
options clause."""
    }

g_nc_keywords['answer-cookie'] = \
    {
        'default': 'yes',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.14.0',
        'topic': 'edns',
        'comment': """answer-cookie is indented as a temporary
measure, for use when named shares an IP address with
other servers that do not yet support DNS COOKIE.  A
mismatch between servers on the same address is not expected
to cause operational problems, but the option to disable
COOKIE response so that all servers have the same behavior
is provided out of an abundance of caution.  DNS COOKIE is
an important security mechanism, and should not be disabled
unless absolutely necessary.

When set to its default value of 'yes', COOKIE.DNS options
will be sent when applicable in replies to client queries.
If set to 'no', COOKIE.EDNS options will not be sent in
replies. This can only be set at global options level,
not per-view."""
    }

g_nc_keywords['attach-cache'] = \
    {
        'default': "",
        'validity': {'function': "view_name"},
        'found-in': {'options', 'view'},
        'introduced': '9.7.0',
        'topic': 'view, cache, caching',
        'comment': """Allows multiple views to share a single cache database.
Each view has its own cache database by default, but
if multiple views have the same operational policy for
name resolution and caching, those views can share a
single cache to save memory and possibly improve
resolution efficiency by using this option. The
attach-cache option may also be specified in view
statements, in which case it overrides the global
attach-cache option.

The cache_name specifies the cache to be shared. When
the named server configures views which are supposed
to share a cache, it creates a cache with the specified
name for the first view of these sharing views. The
rest of the views will simply refer to the already
created cache.

One common configuration to share a cache would be to
allow all views to share a single cache. This can be
done by specifying the attach-cache as a global option
with an arbitrary name.

Another possible operation is to allow a subset of all
views to share a cache while the others to retain
their own caches. For example, if there are three
views A, B, and C, and only A and B should share a
cache, specify the attach-cache option as a view A
(or B)'s option, referring to the other view name:
    view "A" {
        // this view has its own cache
        ...
    };
    view "B" {
        // this view refers to A's cache
        attach-cache "A";
    };
    view "C" {
        // this view has its own cache
    ...
    };
Views that share a cache must have the same policy on
configurable parameters that may affect caching. The
current implementation requires the following
configurable options be consistent among these views:
check-names, cleaning-interval, dnssec-accept-expired,
dnssec-validation, max-cache-ttl, max-ncache-ttl,
max-cache-size, and zero-no-soa-ttl.

Note that there may be other parameters that may cause
confusion if they are inconsistent for different views
that share a single cache. For example, if these views
define different sets of forwarders that can return
different answers for the same question, sharing the
answer does not make sense or could even be harmful.
It is administrator's responsibility to ensure
configuration differences in different views do not
cause disruption with a shared cache.""",
    }

g_nc_keywords['auth-nxdomain'] = \
    {
        'default': 'false',  # was 'yes' in 8.1 # was 'no' in v9.11
        'validity': {'regex': r"(true|false|yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '8.1',
        'topic': 'error status, not found',
        'comment': """If yes, then the AA bit is always set on NXDOMAIN responses, even if the server is not
actually authoritative. The default is no; this is a change from BIND 8. If you are using
very old DNS software, you may need to set it to yes.""",
    }

g_nc_keywords['auto-dnssec'] = \
    {
        'default': "off",
        'validity': {'regex': r"(allow|maintain|off)"},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.7.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """Zones configured for dynamic DNS may use this
option to allow varying levels of automatic DNSSEC key
management. There are three possible settings:
auto-dnssec allow; permits keys to be updated and the
zone fully re-signed whenever the user issues the command
rndc sign zonename.  auto-dnssec maintain; includes the
 above, but also automatically adjusts the zone's DNSSEC
keys on schedule, according to the keys' timing metadata
(see dnssec-keygen(8) and dnssecsettime( 8)). The command
rndc sign zonename causes named to load keys from the key
repository and sign the zone with all keys that are
active. rndc loadkeys zonename causes named to load
keys from the key repository and schedule key
maintenance events to occur in the future, but it does
not sign the full zone immediately. Note: once keys
have been loaded for a zone the first time, the
repository will be searched for changes periodically,
regardless of whether rndc loadkeys is used. The
recheck interval is defined by dnssec-loadkeys-interval.)

When setting a DNSSEC policy ('dnssec-policy' clause) for
a zone instead, the behavior will be as if
`auto-dnssec` was set to `maintain`.

The default setting is auto-dnssec off.
Added to `options` section in v9.9.9.
Added to `view` section in v9.9.9.
Option 'create' removed in v9.9.9.""",
    }

g_nc_keywords['automatic-interface-scan'] = \
    {
        'default': "yes",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.10.3',
        'topic': 'operating system',
        'comment': """If yes and supported by the OS, automatically rescan network interfaces when the interface
addresses are added or removed. The default is yes.
Currently the OS needs to support routing sockets for automatic-interface-scan to be supported.""",
    }

g_nc_keywords['avoid-v4-udp-ports'] = \
    {
        'default': {},
        'validity': {'function': 'port_list'},
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'port, query address, network-interface, UDP',
        'comment': """avoid-v4-udp-ports and avoid-v6-udp-ports can be used to prevent named
from choosing as its random source port a port that is blocked by your
firewall or a port that is used by other applications; if a query went out
with a source port blocked by a firewall, the answer would not get by the
firewall and the name server would have to query again.

Note: the desired range can also be represented only with use-v4-udp-ports
and use-v6-udp-ports, and the "avoid-" options are redundant in that sense;
they are provided for backward compatibility and to possibly simplify the
port specification.""",
    }

g_nc_keywords['avoid-v6-udp-ports'] = \
    {
        'default': {},
        'validity': {'function': 'port_list'},
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'port, query address, network-interface, UDP',
        'comment': """avoid-v4-udp-ports and avoid-v6-udp-ports can be used to prevent named
from choosing as its random source port a port that is blocked by your
firewall or a port that is used by other applications; if a query went out
with a source port blocked by a firewall, the answer would not get by the
firewall and the name server would have to query again.

Note: the desired range can also be represented only with use-v4-udp-ports
and use-v6-udp-ports, and the "avoid-" options are redundant in that sense;
they are provided for backward compatibility and to possibly simplify the
port specification.""",
    }

g_nc_keywords['bindkeys-file'] = \
    {
        'default': "\"/etc/bind.keys\"",
        'validity': {'function': 'path_name'},
        'found-in': {'options'},
        'introduced': '9.5.0',  # Obsoleted in Feb 2017
        'topic': 'operating system, dnssec',
        'comment': """The pathname of a file to override the built-in trusted keys provided by named.

See the discussion of dnssec-lookaside and dnssec-validation for details.

If not specified, the default is /etc/bind.keys.""",
    }

g_nc_keywords['blackhole'] = \
    {
        'default': {0: {'addr': 'none'}},
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'IP, IP4, IP6, dynamic-dns, access control',
        'comment': """Specifies a list of addresses that the server will
not accept queries from or use to resolve a query.

Queries from these addresses will not be responded to.

The default is none.""",
    }

g_nc_keywords['bogus'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'server'},
        'introduced': '8.1',
        'topic': 'testing, test, bogus, remote server, bad data, server-side',
        'comment': """If you discover that a remote server is giving out
bad data, marking it as bogus will prevent further
queries to it. The default value of bogus is no . The
bogus clause is not yet implemented in BIND 9."""
    }

g_nc_keywords['ca-file'] = \
    {
        'default': None,
        'validity': {'quoted_filepath'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'TLS, HTTPS, DoH, server, master, primary',
        'comment': '',
    }

g_nc_keywords['cache-file'] = \
    {
        'default': "",
        'validity': {'function': 'path_name'},
        'found-in': {'options', 'view'},
        'introduced': '9.2.0',
        'obsoleted': '9.18.0',
        'topic': 'testing, test, cache, caching',
        'comment': """This is for testing only. Do not use.""",
    }

g_nc_keywords['catalog-zones'] = \
    {
        'occurs-multiple-times': False,
        'topblock': False,
        'introduced': '9.11.0',
        'found-in': {'options', 'view'},  # added 'options' around 9.15.
    }

g_nc_keywords['category'] = \
    {
        'default': None,
        'validity': {'regex': r'\s',
                     'function': 'channel_name'},
        'found-in': {'logging'},
        'user-defined-indices': True,  # channel_name
        'multi-line-order-id': 2,
        'occurs-multiple-times': True,
        'introduced': '9.0.0',
        'topic': 'logging',
        'comment': '',
    }

g_nc_keywords['cert-file'] = \
    {
        'default': None,
        'validity': {'quoted_filepath'},
        'found-in': {'tls'},  # was in 'primaries'? in v9.18?
        'introduced': '9.19.0',
        'topic': 'TLS, HTTPS, DoH, server, master, primary',
        'comment': '',
    }

g_nc_keywords['channel'] = \
    {
        'default': None,
        'validity': {'regex': r'\s',
                     'function': 'channel_name'},
        'found-in': {'logging'},
        'user-defined-indices': True,  # channel_name
        'occurs-multiple-times': True,
        'multi-line-order-id': 1,
        'introduced': '9.0.0',
        'topic': 'logging',
        'comment': """ Clause 'buffered' introduced in v9.10.0 """,
    }

g_nc_keywords['check-dup-records'] = \
    {
        'default': 'warn',
        'validity': {'regex': r'(warn|fail|ignore)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.7.0',
        'topic': 'validation',
        'zone-type': {'master', 'primary'},
        'comment': """Check master zones for records that are treated as different by DNSSEC but are semantically
equal in plain DNS. The default is to warn. Other possible values are fail and
ignore.""",
    }

g_nc_keywords['check-integrity'] = \
    {
        'default': "yes",
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'validation',
        'zone-type': {'master', 'primary'},
        'comment': """Perform post load zone integrity checks on master
zones. This checks that MX and SRV records refer to
address (A or AAAA) records and that glue address
records exist for delegated zones. For MX and SRV
records only in-zone hostnames are checked (for
outof-zone hostnames use named-checkzone). For NS
records only names below top of zone are checked (for
out-of-zone names and glue consistency checks use
named-checkzone).
The default is yes.
The use of the SPF record for publishing Sender
Policy Framework is deprecated as the migration from
using TXT records to SPF records was abandoned.
Enabling this option also checks that a TXT Sender
Policy Framework record exists (starts with "v=spf1")
if there is an SPF record. Warnings are emitted if the
TXT record does not exist and can be suppressed with
check-spf.""",
    }

g_nc_keywords['check-mx'] = \
    {
        'default': 'warn',
        'validity': {'regex': r"(warn|fail|ignore)"},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'zone, integrity, SMTP, validation',
        'zone-type': {'master', 'primary'},
        'comment': """Check whether the MX record appears to refer to a IP
address. The default is to warn.
Other possible values are fail and ignore.""",
    }

g_nc_keywords['check-mx-cname'] = \
    {
        'default': 'warn',
        'validity': {'regex': r"(warn|fail|ignore)"},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'zone, integrity, SMTP, validation',
        'zone-type': {'master', 'primary'},
        'comment': """If check-integrity is set then fail, warn or ignore
MX records that refer to CNAMES.
The default is to warn.""",
    }

g_nc_keywords['check-names'] = \
    {
        'default': {0: {'primary fail'},
                    1: {'secondary warn'},
                    2: {'response ignore'},
                    },  # change from 'master' in v9.13
        'validity': {'regex': r"(primary|master|slave|secondary|response)\s+(warn|fail|ignore)"},
        'found-in': {'options', 'view', 'zone'},
        'occurs-multiple-times': True,
        # In 8.2, found in ['zone']['type']['master']
        # In 8.2, found in ['zone']['type']['slave']
        # In 8.2, found in ['zone']['type']['stub']
        # In 8.2, found in ['zone']['type']['hint']
        'introduced': '8.1',
        'topic': 'integrity, validation',
        'zone-type': {'master', 'slave', 'mirror', 'hint', 'stub', 'primary', 'secondary'},
        'comment': """This option is used to restrict the character set and
syntax of certain domain names in master files and/or
DNS responses received from the network.
The default varies according to usage area.

For master zones the default is fail.
For slave zones the default is warn.
For answers received from the network (response) the
default is ignore.

The rules for legal hostnames and mail domains are
derived from RFC 952 and RFC 821 as modified by RFC
1123. check-names applies to the owner names of A,
AAAA and MX records. It also applies to the domain
names in the RDATA of NS, SOA, MX, and SRV records.

It also applies to the RDATA of PTR records where
the owner name indicated that it is a reverse
lookup of a hostname (the owner name ends in
IN-ADDR.ARPA, IP6.ARPA, or IP6.INT).""",
    }

g_nc_keywords['check-sibling'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'validation',
        'zone-type': {'master', 'primary'},
        'comment': """When performing integrity checks, also check that
sibling glue exists. The default is yes.""",
    }

g_nc_keywords['check-spf'] = \
    {
        'default': 'warn',
        'validity': {'regex': r'(warn|fail|ignore)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.6',
        'topic': 'validation',
        'zone-type': {'master', 'primary'},
        'comment': """If check-integrity is set then check that there is a
TXT Sender Policy Framework record present (starts
with "v=spf1") if there is an SPF record present.
The default is warn.""",
    }

g_nc_keywords['check-srv-cname'] = \
    {
        'default': 'warn',
        'validity': {'regex': r'(warn|fail|ignore)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'validation',
        'zone-type': {'master', 'primary'},
        'comment': """If check-integrity is set then fail, warn or
ignore SRV records that refer to CNAMES.
The default is to warn.""",
    }

g_nc_keywords['check-wildcard'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'validation',
        'zone-type': {'master', 'primary'},
        'comment': """This option is used to check for non-terminal
wildcards. The use of non-terminal wildcards is
almost always as a result of a failure to understand
the wildcard matching algorithm (RFC 1034). This
option affects master zones. The default (yes) is to
check for non-terminal wildcards and issue a warning.""",
    }

g_nc_keywords['ciphers'] = \
    {
        'default': None,
        'validity': {'string'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'TLS, HTTPS, DoH, server, master, primary',
        'comment': '',
    }

g_nc_keywords['class'] = \
    {
        'default': 'IN',
        'validity': {'regex': r'(IN|CH|HS)'},
        'found-in': {'rrset-order'},
        'introduced': '9.0.0',
        'topic': 'class, network layer',
        'comment': '',
    }

g_nc_keywords['cleaning-interval'] = \
    {
        'default': '60',
        'validity': {'range': {0, 1440}},
        'unit': 'minute',
        'found-in': {'options', 'view'},
        'introduced': '8.2',
        'obsoleted': '9.16',
        'topic': 'inert, server resource, periodic task, cache, caching',
        'comment':
            """This interval is effectively obsolete. Previously,
            the server would remove expired resource records from
            the cache every cleaning-interval minutes. Manages
            cache memory in a more sophisticated manner and does
            not rely on the periodic cleaning specifying this option
            therefore has no effect on the server's behavior.
            If set to 0, no periodic cleaning will occur.""",
    }

g_nc_keywords['clients-per-query'] = \
    {
        'default': 10,
        'validity': {'range': {0, 300}},
        'found-in': {'options', 'view'},
        'introduced': '9.5.0',
        'topic': 'rate limit, filtering, server resource',
        'comment':
            """These set the initial value (minimum) and maximum
            number of recursive simultaneous clients for any given
            query (<qname,qtype,qclass>) that the server will
            accept before dropping additional clients. named will
            attempt to self tune this value and changes will be
            logged.
            
            The default values are 10 and 100.
            
            This value should reflect how many queries come in
            for a given name in the time it takes to resolve that
            name. If the number of queries exceed this value,
            named will assume that it is dealing with a
            non-responsive zone and will drop additional queries.
            If it gets a response after dropping queries, it will
            raise the estimate. The estimate will then be lowered
            in 20 minutes if it has remained unchanged.
            
            If clients-per-query is set to zero, then there is no
            limit on the number of clients per query and no
            queries will be dropped.
            
            If max-clients-per-query is set to zero, then there
            is no upper bound other than imposed by
            recursive-clients.""",
    }

g_nc_keywords['cookie-algorithm'] = \
    {
        'default': 'siphash24',  # since 9.12
        'validity': {'regex': r'(aes|siphash24|sha1|sha256)'},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'topic': 'TCP, network',
        'comment': '',
    }

g_nc_keywords['cookie-secret'] = \
    {
        'default': None,
        'validity': {'string'},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'occurs-multiple-times': True,
        'topic': 'TCP, network',
        'comment': '',
    }

g_nc_keywords['coresize'] = \
    {
        'default': 'default',  # changed from 'unlimited' in v9.12
        'validity': {'function': 'size_spec',
                     'regex': r'(default|unlimited)'},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system',
        'comment': """The maximum size of a core dump. The default is default.""",
    }

g_nc_keywords['database'] = \
    {
        'default': 'rbt',
        'validity': 'string',
        'found-in': {'dlz'},
        'introduced': '9.1',
        'topic': 'operating-system, database',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'primary', 'secondary'},
        'comment': '',
    }

g_nc_keywords['datasize'] = \
    {
        'default': 'default',  # changed from 'unlimited' in v9.12
        'validity': {'function': 'size_spec',
                     'regex': '(default|unlimited)'},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system, cache, caching',
        'comment': """The maximum amount of data memory the server may use.

The default is default.

This is a hard limit on server memory usage. If the
server attempts to allocate memory in excess of this
limit, the allocation will fail, which may in turn
leave the server unable to perform DNS service.

Therefore, this option is rarely useful as a way of
limiting the amount of memory used by the server, but
it can be used to raise an operating system data size
limit that is too small by default.

If you wish to limit the amount of memory used by the
server, use the max-cache-size and
recursive-clients options instead.""",
    }

g_nc_keywords['deallocate-on-exit'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options'},
        'introduced': '8.2',
        'deprecated': '9.0',
        'obsoleted': '9.18.0',
        'topic': 'operating-system, ignored',
        'comment': """This option was used in BIND 8 to enable checking for memory leaks on exit.
BIND 9 ignores the option and always performs the checks.""",
    }

g_nc_keywords['delegation-only'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'zone'},
        'introduced': '9.3.0',
        'topic': 'query, forwarding',
        'zone-type': {'hint', 'stub', 'forward'},
        'comment': '',
    }

g_nc_keywords['deny-answer-addresses'] = \
    {
        'default': None,
        'validity': {'function': 'address_match_list'},
        'found-in': {'options', 'view'},
        'introduced': '9.7.0',
        'topic': 'query, content filtering',
        'comment': '',
    }

g_nc_keywords['deny-answer-aliases'] = \
    {
        'default': None,
        'validity': {'function': 'domain_list'},
        'found-in': {'options', 'view'},
        'introduced': '9.7.0',
        'topic': 'query, alias, content filtering',
        'comment': '',
    }

g_nc_keywords['dhparam-file'] = \
    {
        'default': None,
        'validity': {'quoted_filepath'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'TLS, HTTPS, DoH, server, master, primary',
        'comment': '',
    }

g_nc_keywords['dialup'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no|notify|refresh|passive|notify\-passive)'},
        # In 8.2 to 9.0, 'validity': r'(yes|no)'
        'found-in': {'options', 'view', 'zone'},
        # In 8.2, only found in ['zone']['type']['master']
        'introduced': '8.2',
        'topic': 'operating-system, slow-modem',
        'zone-type': {'master', 'slave', 'stub', 'primary', 'secondary'},
        'comment': """If yes, then the server treats all zones as if they
are doing zone transfers across a dial-ondemand
dialup link, which can be brought up by traffic
originating from this server. This has different
effects according to zone type and concentrates the
zone maintenance so that it all happens in a short
interval, once every heartbeat-interval and hopefully
during the one call. It also suppresses some of the
normal zone maintenance traffic.

The default is no.

The dialup option may also be specified in the view
and zone statements, in which case it overrides the
global dialup option.

If the zone is a master zone, then the server will
send out a NOTIFY request to all the slaves (default).
This should trigger the zone serial number check in
the slave (providing it supports NOTIFY) allowing
the slave to verify the zone while the connection
is active.

The set of servers to which NOTIFY is sent can be
controlled by notify and also-notify.

If the zone is a slave or stub zone, then the server
will suppress the regular "zone up to date" (refresh)
queries and only perform them when the
heartbeat-interval expires in addition to sending
NOTIFY requests.

Finer control can be achieved by using notify which
only sends NOTIFY messages, notify-passive which
sends NOTIFY messages and suppresses the normal
refresh queries, refresh which suppresses normal
refresh processing and sends refresh queries when the
heartbeat-interval expires, and passive which just
disables normal refresh processing.""",
    }

g_nc_keywords['directory'] = \
    {
        'default': "\".\"",
        'validity': {'function': 'path_name'},
        'found-in': {'options'},
        'introduced': '4.8',
        'topic': 'operating-system',
        'comment': """The working directory of the server. Any non-absolute
pathnames in the configuration file will be taken as
relative to this directory. The default location for
most server output files (e.g. named.run) is this
directory.

If a directory is not specified, the working
directory defaults to '.', the directory from which
the server was started. The directory specified
should be an absolute path.""",
    }

g_nc_keywords['disable-algorithms'] = \
    {
        'occurs-multiple-times': True,
        'default': '',
        'validity': {'function': 'algorithm_list'},
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',
        'topic': 'DNSSEC',
        'comment': """
Disable the specified DNSSEC algorithms at and below
the specified name.

Multiple disable-algorithms statements are allowed.

Only the best match disable-algorithms clause will be
used to determine which algorithms are used.

If all supported algorithms are disabled, the zones
covered by the disable-algorithms will be treated as
insecure.""",
    }

g_nc_keywords['disable-ds-digests'] = \
    {
        'occurs-multiple-times': True,
        'default': '',
        'validity': {'function': 'digest_list'},
        'found-in': {'options', 'view'},
        'introduced': '9.11',
        'topic': 'DNSSEC',
        'comment': """Disable the specified DS/DLV digest types at and
below the specified name. Multiple disable-ds-digests
statements are allowed. Only the best match
disable-ds-digests clause will be used to determine
which digest types are used.

If all supported digest types are disabled, the zones
covered by the disable-ds-digests will be treated
as insecure.""",
    }

g_nc_keywords['disable-empty-zone'] = \
    {
        'occurs-multiple-times': True,
        'default': '',
        'validity': {'function': 'hostname'},
        'unit': 'empty_zone_name',
        'found-in': {'options', 'view'},
        'introduced': '4.9.2',
        'topic': 'zone, empty zone',
        'comment': """Disable individual empty zones.
By default, none are disabled.

This option can be specified multiple times""",
    }

g_nc_keywords['dns64'] = \
    {
        'default': "no",
        'validity': {'boolean': {'no'},
                     'function': "prefix_64"},
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'occurs-multiple-times': True,
        'topic': 'ip6, dnssec',
        'comment': """This directive instructs named to return mapped IPv4
addresses to AAAA queries when there are no AAAA
records. It is intended to be used in conjunction with
a NAT64. Each dns64 defines one DNS64 prefix. Multiple
DNS64 prefixes can be defined.
Compatible IPv6 prefixes have lengths of 32, 40, 48,
56, 64 and 96 as per RFC 6052.
Additionally a reverse IP6.ARPA zone will be created
for the prefix to provide a mapping from the IP6.ARPA
names to the corresponding IN-ADDR.ARPA names using
synthesized CNAMEs. dns64-server and dns64-contact can
be used to specify the name of the server and contact
for the zones.
These are settable at the view / options level.
These are not settable on a per-prefix basis. Each
dns64 supports an optional clients ACL that determines
which clients are affected by this directive.

If not defined, it defaults to any;.
Each dns64 supports an optional mapped ACL that selects
which IPv4 addresses are to be mapped in the
corresponding A RRset. If not defined it defaults to any;.
Normally, DNS64 won't apply to a domain name that owns one
or more AAAA records; these records will simply be
returned. The optional exclude ACL allows specification of
a list of IPv6 addresses that will be ignored if they
appear in a domain name's AAAA records, and DNS64 will be
applied to any A records the domain name owns. If not
defined, exclude defaults to ::ffff:0.0.0.0/96.
A optional suffix can also be defined to set the bits
trailing the mapped IPv4 address bits.
By default these bits are set to ::. The bits matching
the prefix and mapped IPv4 address must be zero.

If recursive-only is set to yes the DNS64 synthesis will
only happen for recursive queries.

The default is no.

If break-dnssec is set to yes the DNS64 synthesis will
happen even if the result, if validated, would cause a
DNSSEC validation failure. If this option is set to no
(the default), the DO is set on the incoming query, and
there are RRSIGs on the applicable records, then
synthesis will not happen.
acl rfc1918 { 10/8; 192.168/16; 172.16/12; };
dns64 64:FF9B::/96 {
    clients { any; };
    mapped { !rfc1918; any; };
    exclude { 64:FF9B::/96; ::ffff:0000:0000/96; };
    suffix ::;
};""",
    }

g_nc_keywords['dns64-contact'] = \
    {
        'default': None,
        'validity': None,
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'topic': 'ip6, dnssec',
        'comment': '',
    }

g_nc_keywords['dns64-server'] = \
    {
        'default': None,
        'validity': None,
        'introduced': '9.8.0',
        'found-in': {'options', 'view'},
        'topic': 'dnssec, inert',
        'comment': '',
    }

g_nc_keywords['dnskey-sig-validity'] = \
    {
        'default': 0,
        'validity': {'range': {0, 3660}},
        'unit': 'day',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.13.0',
        'deprecated': '9.15.6',
        'topic': 'dnssec, tuning',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """
This option has been replaced in favor of the KASP
configuration value `signatures-validity-dnskey`.
""",
    }

g_nc_keywords['dnsrps-enable'] = \
    {
        'default': None,
        'validity': {'regex': r'(yes)|(no)'},
        'introduced': '9.12',
        'found-in': {'options', 'view'},
        'topic': 'policy, RPZ rewriting',
        'comment': """The dnsrps-enable yes option turns on the DNS Response
Policy Server (DNSRPS) interface, if it has been compiled
to named using configure --enable-dnsrps.
The dnsrps-options block provides additional RPZ
configuration settings, which are passed throught to the
DNSRPS proivder library.  Multiple DNSRPS settings in an
dnsrps-options string should be separated with semi-colons.
The DNSRPS provider librpz, is passed a configuration
string consisting of the dnsrps-options text, concatenated
with settings derived from the response-policy statement.  """,
    }

g_nc_keywords['dnsrps-options'] = \
    {
        'default': None,
        'validity': {'string'},
        'introduced': '9.12',
        'found-in': {'options', 'view'},
        'topic': 'policy, inert, RPZ rewriting',
        'comment': '',
    }

g_nc_keywords['dnskey-ttl'] = \
    {
        'default': '1h',
        'validity': {'function': 'iso8601_time_duration'},
        'unit': 'second_unless_stated',
        'introduced': '9.15.6',
        'found-in': {'dnssec-policy'},
        'topic': 'DNSSEC',
        'comment': """
The TTL to use when generating DNSKEY resource reocrds.
The default is 1 hour (3660 seconds).
""",
    }

g_nc_keywords['dnskey-sig-validity'] = \
    {
        'default': 0,
        'validity': {'regex': r'\d+'},
        'unit': 'duration',
        'introduced': '9.15.0',  # document-only in 9.8.0
        'found-in': {'options', 'view', 'zone'},
        'topic': 'DNSSEC',
        'zone-type': {'master', 'primary', 'secondary', 'slave'},
        'comment': """Specifies the number of days into the future when
DNSSEC signatures that are automatically generated for
DNSKEY RRsets as a result of dynamic updates will expire.
If set to non-zero value, this overrides the value set by
sig-validity-interval. The default is zero, meaning
sig-validity-interval is used. The maximum value is 3660
days (10 years), and higher values will be rejected.""",
    }

g_nc_keywords['dnsrps-enable'] = \
    {
        'default': None,
        'validity': {'regex': r'(yes)|(no)'},
        'introduced': '9.12',
        'found-in': {'options', 'view'},
        'topic': 'policy, RPZ rewriting',
        'comment': """The dnsrps-enable yes option turns on the DNS Response
Policy Server (DNSRPS) interface, if it has been compiled
to named using configure --enable-dnsrps.
The dnsrps-options block provides additional RPZ
configuration settings, which are passed throught to the
DNSRPS proivder library.  Multiple DNSRPS settings in an
dnsrps-options string should be separated with semi-colons.
The DNSRPS provider librpz, is passed a configuration
string consisting of the dnsrps-options text, concatenated
with settings derived from the response-policy statement.  """,
    }

g_nc_keywords['dnsrps-options'] = \
    {
        'default': None,
        'validity': {'string'},
        'introduced': '9.12',
        'found-in': {'options', 'view'},
        'topic': 'policy, inert, RPZ rewriting',
        'comment': '',
    }

g_nc_keywords['dnssec-accept-expired'] = \
    {
        'default': 'no',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """
This option will be removed and the key configuration from
the policy will be used to determine what RRsets will be
signed with which keys (Keys will have a role "KSK" and/or "ZSK").

When this option and update-check-ksk are
both set to yes, only key-signing keys (that is, keys with
the KSK bit set) will be used to sign the DNSKEY RRset at
the zone apex.  Zone-signing keys (keys without the KSK bit
set) will be used to sign the remainder of the zone, but
not the DNSKEY RRset. This is similar to the
dnssec-signzone -x command line option.

The default is no.

If update-check-ksk is set to no, this option is ignored.""",
    }

g_nc_keywords['dnssec-enable'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',
        'obsoleted': '9.15.1',
        'topic': 'DNSSEC',
        'comment': """This indicates whether DNSSEC-related resource
records are to be returned by named.  If set to no, named
will not return DNSSEC-related resource records unless
specifically queried for. The default is yes.""",
    }

g_nc_keywords['dnssec-dnskey-kskonly'] = \
    {
        'default': 'no',
        'validity': {'boolean'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.7.0',
        'topic': 'DNSSEC',
        'zone-type': {'primary', 'secondary', 'master', 'slave'},
        'comment': ''
    }

g_nc_keywords['dnssec-loadkeys-interval'] = \
    {
        'default': 60,
        'validity': {'range': {1, 1440}},
        'unit': 'minute',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.9.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """When a zone is configured with auto-dnssec
maintain; its key repository must be checked periodically
to see if any new keys have been added or any existing
keys' timing metadata has been updated (see dnssec-keygen(8)
and dnssec-settime(8)). The dnssec-loadkeysinterval option
sets the frequency of automatic repository checks, in
minutes.

This option will determine how the period that BIND 9
will check its key repository (default once per hour)
to see if there are new keys added or if existing keys
metadata has changed.  This option might go away
because the entity that performs DNSSEC maintenance
knows exactly when the next step needs to happen. We
can set the interval accordingly.  This does mean that
whenever a new key is added or deprecated manually,
the interval needs to be set to now.  Alternatively,
we keep this option and only pick up new keys when at
a certain interval.

The default is 60 (1 hour), the minimum is 1 (1
minute), and the maximum is 1440 (24 hours); any higher value
is silently reduced.
If set to 0, no heartbeat will occur.""",
    }

g_nc_keywords['dnssec-lookaside'] = \
    {
        'default': '',
        'validity': {
            'regex': r'(auto|no|([A-Za-z0-9_\-]+)(\.[A-Za-z0-9_\-])'
                     r'+\s+(domain)\s+([A-Za-z0-9_\-]+)(\.[A-Za-z0-9_\-])+\))'},
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',  # 'auto' added in 9.7
        'obsoleted': '9.16.0',
        'topic': 'DNSSEC',
        'comment':
            """Syntax: dnssec-lookaside ( auto | no | domain trust-anchor domain ) ; ]
            Disable the specified DS/DLV digest types at and below the
            specified name. Multiple disable-ds-digests statements are
            allowed. Only the best match disable-ds-digests clause
            will be used to determine which digest types are used.
            If all supported digest types are disabled, the zones
            covered by the disable-ds-digests will be treated as
            insecure.
            
            NOTE: named now provides feedback to the owners of zones
            which have trust anchors configured (trusted-keys,
            managed-keys, dnssec-validation auto; and
            dnssec-lookaside auto;) by sending a daily query which
            encodes the keyids of the configured trust anchors for
            the zone. This is controlled by trust-anchor-telemetry
            and defaults to yes.""",
    }

g_nc_keywords['dnssec-must-be-secure'] = \
    {
        'default': '',
        'occurs-multiple-times': True,
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',
        'topic': 'DNSSEC',
        'comment':
            """Specify hierarchies which must be or may not be secure
            (signed and validated). If yes, then named will only
            accept answers if they are secure. If no, then normal
            DNSSEC validation applies allowing for insecure answers
            to be accepted. The specified domain must be under a
            trusted-keys or managed-keys statement, or
            dnssec-lookaside must be active.""",
    }

g_nc_keywords['dnssec-policy'] = \
    {
        # This is one of those split-syntax/same-name between top-level and options
        'default': 'none',
        'validity': {'function': 'dnssec_policy_name',
                     'regex': '(none|default)'},
        'occurs-multiple-times': False,
        'topblock': True,
        'required': False,  # depends on topblock 'dnssec-policy'
        'found-in': {'', 'options', 'view', 'zone'},
        'introduced': '9.17.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': '',
    }

g_nc_keywords['dnssec-secure-to-insecure'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.7.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'primary'},
        'comment':
            """Allow a dynamic zone to transition from secure to
insecure (i.e., signed to unsigned) by deleting all of
the DNSKEY records.

The default is no.

If set to yes, and if the DNSKEY RRset at the zone
apex is deleted, all RRSIG and NSEC records will be
removed from the zone as well.

This option allows a dynamic zone to transition from
secure to insecure.  This seems to be a safety check
when named is not responsible for signing.  This will
likely go away because explicitly removing the
dnssec-policy will be the same signal to (safely)
make the zone insecure.

If the zone uses NSEC3, then it is also necessary to
delete the NSEC3PARAM RRset from the zone apex; this will
cause the removal of all corresponding NSEC3 records.
(It is expected that this requirement will be eliminated
in a future release.)

Note that if a zone has been configured with auto-dnssec
maintain and the private keys remain accessible in the
key repository, then the zone will be automatically
signed again the next time named is started.""",
    }

g_nc_keywords['dnssec-update-mode'] = \
    {
        'default': 'maintain',
        'validity': {'regex': r'(maintain|no\-resign|external)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.9.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """If this option is set to its default value of
maintain in a zone of type master which is
DNSSEC-signed and configured to allow dynamic
updates (see Section 6.2), and if named has access
to the private signing key(s) for the zone, then
named will automatically sign all new or changed
records and maintain signatures for the zone by
regenerating RRSIG records whenever they approach
their expiration date.
If the option is changed to no-resign, then named
will sign all new or changed records, but scheduled
maintenance of signatures is disabled.
With either of these settings, named will reject
updates to a DNSSEC-signed zone when the signing keys
are inactive or unavailable to named. (A planned
third option, exter nal, will disable all automatic
signing and allow DNSSEC data to be submitted into a
zone via dynamic update; this is not yet implemented.)""",
    }

g_nc_keywords['dnssec-validation'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no|auto)'},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'DNSSEC',
        'comment':
            """Enable DNSSEC validation in named. Note dnssec-enable
            also needs to be set to yes to be effective. If set to
            no, DNSSEC validation is disabled. If set to auto,
            DNSSEC validation is enabled, and a default trust-anchor
            for the DNS root zone is used. If set to yes, DNSSEC
            validation is enabled, but a trust anchor must be
            manually configured using a trusted-keys or managed-keys
            statement. The default is yes.
            NOTE: Whenever the resolver sends out queries to an
            EDNS-compliant server, it always sets the DO bit
            indicating it can support DNSSEC responses even if
            dnssec-validation is off.
            Note: 'auto' option added in v9.8.0.""",
    }

g_nc_keywords['dnstap'] = \
    {
        'default': '',
        'validity': {'function': 'dnstap_args'},
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'capture, operating-system, inert',
        'comment':
            """dnstap is a fast, flexible method for capturing and
            logging DNS traffic.  Developed by Robert Edmonds at
            Farsight Security, Inc. and supported by multiple
            DNS implementation, dnstap uses libfstrm (a lightweight
            high-speed framing library; see
            https://github.com/farsight to send event payloads which
            are encoded using Protocol Buffers (libprotobuf-c; a
            mechanism for serializing structured data developed by
            Google, Inc. (see
            https://developers.google.com/protocolbuffers).
            
            To enable dnstap at compile time, the fstrm and
            protobuf-c libraries must be available, and BIND must be
            configured with --enable-dnstap.
            
            The dnstap option is a bracketed list of message types to
            be logged.  These may be set differently for each view.
            Supported types are client, resolver, forwarder, and
            update.  Specifying type all will cause all dnstap
            messages to be logged, regardless of type.
            Each type may take on an additional argument to indicate
            whether to log query messages or response messages; if
            not specified, both queries and responses are logged.
            Option 'dnstap' series activated in v9.14.0.""",
    }

g_nc_keywords['dnstap-identity'] = \
    {
        'default': '',
        'validity': {'function': 'dscp_identity'},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'topic': 'capture, tap, operating-system, inert',
        'comment': '',
    }

g_nc_keywords['dnstap-output'] = \
    {
        'default': '',
        'validity': {'function': 'dscp_output'},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'topic': 'capture, tap, operating-system, inert',
        'comment': """
Option 'dnstap-output' activated at v9.12.0
""",
    }

g_nc_keywords['dnstap-version'] = \
    {
        'default': '',
        'validity': {'function': 'dscp_version'},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'topic': 'capture, tap, operating-system, inert',
        'comment':
            """Specifies a version string to send in dnstap messages.
            The default is the version number of the BIND release.
            If set to none, no version string will be sent.""",
    }

g_nc_keywords['dscp'] = \
    {
        'default': '',
        'validity': {'range': {0, 63}},
        'found-in': {'options', 'also-notify', 'primaries', 'masters',
                     'alt-transfer-source', 'alt-transfer-source-v6',
                     'forwarders', 'parental-source', 'parental-source-v6',
                     'query-source', 'query-source-v6', 'parental-agents'},
        'introduced': '9.10.0',
        'topic': 'operating-system, DSCP',
        'comment': """The global Differentiated Services Code
Point (DSCP) value to classify outgoing DNS traffic on
operating systems that support DSCP. Valid values
are 0 through 63. It is not configured by default.""",
    }

g_nc_keywords['dual-stack-servers'] = \
    {
        'default': '',
        'validity': {'function': 'addr_list'},
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',
        'topic': 'operating-system, dual-stack, dscp',
        'comment': """Specifies host names or addresses of machines with
access to both IPv4 and IPv6 transports.

If a hostname is used, the server must be able to
resolve the name using only the transport it has. If
the machine is dual stacked, then the
dual-stack-servers have no effect unless access to a
transport has been disabled on the command line
(e.g. named -4).""",
    }

g_nc_keywords['dump-file'] = \
    {
        'default': '"named_dump.db"',
        'validity': {'function': 'path_name'},
        'found-in': {'options'},
        'introduced': '8.1',  # inert at 9.0.0, active at 9.6.3
        'topic': 'operating-system, rndc, inert',
        'comment': """The pathname of the file the server dumps the
database to when instructed to do so with rndc dumpdb.

If not specified, the default is named_dump.db.""",
    }

g_nc_keywords['edns'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'server'},
        'introduced': '9.3',
        'topic': 'EDNS, server-side',
        'comment': """The edns clause determines whether the local server
will attempt to use EDNS when communicating with the
remote server. The default is yes.""",
    }

g_nc_keywords['edns-udp-size'] = \
    {
        'default': '1232',
        'validity': {'range': {512, 4096}},
        'unit': 'udp_buffer_byte_size',
        'found-in': {'options', 'server', 'view'},
        'introduced': '9.3',  # was in v8.4, gone in v9.0
        'topic': 'EDNS, udp, transport layer, tuning, server-side',
        'comment': """Sets the maximum advertised EDNS UDP buffer size in
bytes, to control the size of packets received from
authoritative servers in response to recursive queries.
Valid values are 512 to 4096 (values outside this range
will be silently adjusted to the nearest value within
it).

The default value is 4096.

The usual reason for setting edns-udp-size to a
non-default value is to get UDP answers to pass
through broken firewalls that block fragmented packets
and/or block UDP DNS packets that are greater than
512 bytes.

When named first queries a remote server, it will
advertise a UDP buffer size of 512, as this has the
greatest chance of success on the first try.

If the initial response times out, named will try
again with plain DNS, and if that is successful, it
will be taken as evidence that the server does not
support EDNS. After enough failures using EDNS and
successes using plain DNS, named will default to
plain DNS for future communications with that server.
(Periodically, named will send an EDNS query to see
if the situation has improved.)

However, if the initial query is successful with EDNS
advertising a buffer size of 512, then named will
advertise progressively larger buffer sizes on
successive queries, until responses begin timing out
or edns-udp-size is reached.

The default buffer sizes used by named are 512, 1232,
1432, and 4096, but never exceeding edns-udp-size.
(The values 1232 and 1432 are chosen to allow for an
IPv4/IPv6 encapsulated UDP message to be sent without
fragmentation at the minimum MTU sizes for Ethernet
and IPv6 networks.)""",
    }

g_nc_keywords['edns-version'] = \
    {
        'default': '0',
        'validity': {'range': {0, 255}},
        'found-in': {'server'},
        'introduced': '9.11',
        'topic': 'EDNS, server-side',
        'comment': """The edns-version options sets the maximum EDNS version
that will be sent to the server(s) by the resolver.  The actual EDNS version
version is still subject to normal EDNS version negotiation rules (RFC 6891),
the maximum EDNS version supported by the server, and any other heuristics that
indicates a lower version should be sent.  This option is intended to be used
when a remote server reacts badly to a given EDNS version or higher; it should
be set to highest version is known to support. Valid values are 0 to 255; higher
values will be silently adjusted. This option will not be needed until higher
EDNS versions than 0 are in use."""
    }

g_nc_keywords['empty-contact'] = \
    {
        'default': '.',
        'validity': {'function': 'fully_qualified_domain_name'},
        'unit': 'empty_zone_name',
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'empty zone',
        'comment': """Specify what contact name will appear in the returned
SOA record for empty zones.

If none is specified, then "." will be used.""",
    }

g_nc_keywords['empty-server'] = \
    {
        'default': 'zone_soa_name',
        'validity': {'function': 'fully_qualified_domain_name'},
        'unit': 'empty_zone_name',
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'empty zone',
        'comment': """Specify what server name will appear in the returned
SOA record for empty zones.

If none is specified, then the zone's name will be used.""",
    }

g_nc_keywords['empty-zones-enable'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(no|yes)'},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'empty zone',
        'comment': """Enable or disable all empty zones. By default, they are enabled.""",
    }

g_nc_keywords['endpoints'] = \
    {
        'default': None,
        'validity': {'list_of_quoted_string'},
        'found-in': {'http'},
        'introduced': '9.15.7',
        'topic': 'HTTP, DoH, TLS',
        'comment': '',
    }

g_nc_keywords['fake-iquery'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options'},
        'introduced': '8.1',
        'obsoleted': '9.6.3',
        'topic': 'inert',
        'comment': """In BIND 8, this option enabled simulating the obsolete DNS query type IQUERY. BIND 9
never does IQUERY simulation.""",
    }

g_nc_keywords['fetch-glue'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '8.1',
        'obsoleted': '9.7.0',
        'topic': 'inert',
        'comment': """This option is obsolete. In BIND 8, fetch-glue yes
caused the server to attempt to fetch glue resource
records it didn't have when constructing the
additional data section of a response. This is now
considered a bad idea and BIND 9 never does it.""",
    }

g_nc_keywords['fetch-quota-params'] = \
    {
        'default': {100, 0.1, 0.3, 0.7},  # Don't provide a default, it's a BIND9 compile-option
        'validity': {'function': 'fetch_quota'},
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'server resource',
        'comment':
            """Sets the parameters to use for dynamic resizing of the
            fetches-per-server quota in response to detected
            congestion.
            The first argument is an integer value indicating how
            frequently to recalculate the moving average of the ratio
            of timeouts to responses for each server. The default
            is 100, meaning we recalculate the average ratio after
            every 100 queries have either been answered or timed out.
            The remaining three arguments represent the "low"
            threshold (defaulting to a timeout ratio of 0.1), the
            "high" threshold (defaulting to a timeout ratio of 0.3),
            and the discount rate for the moving average (defaulting
            to 0.7). A higher discount rate causes recent events to
            weigh more heavily when calculating the moving average;
            a lower discount rate causes past events to weigh more
            heavily, smoothing out short-term blips in the timeout
            ratio.
            These arguments are all fixed-point numbers with
            precision of 1/100: at most two places after the decimal
            point are significant.
            (Note: This option is only available when BIND is built
            with configure --enable-fetchlimit.)""",
    }

g_nc_keywords['fetches-per-server'] = \
    {
        'default': {'0'},  # used to be '0 drop' in v9.11
        'validity': None,
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'server resource',
        'comment':
            """The maximum number of simultaneous iterative queries
            that the server will allow to be sent to a single
            upstream name server before blocking additional queries.
            This value should reflect how many fetches would normally
            be sent to any one server in the time it would take to
            resolve them. It should be smaller than recursive-clients.
            Optionally, this value may be followed by the keyword drop
            or fail, indicating whether queries will be dropped with
            no response, or answered with SERVFAIL, when all of the
            servers authoritative for a zone are found to have
            exceeded the per-server quota. The default is fail.
            If fetches-per-server is set to zero, then there is no
            limit on the number of fetches per query and no queries
            will be dropped. The default is zero.
            The fetches-per-server quota is dynamically adjusted in
            response to detected congestion.
            As queries are sent to a server and are either answered or
            time out, an exponentially weighted moving average is
            calculated of the ratio of timeouts to responses. If the
            current average timeout ratio rises above a "high"
            threshold, then fetches-per-server is reduced for that
            server. If the timeout ratio drops below a "low"
            threshold, then fetches-per-server is increased. The
            fetch-quota-params options can be used to adjust the
            parameters for this calculation.
            (Note: This option is only available when BIND is built
            with configure --enable-fetchlimit.)""",
    }

g_nc_keywords['fetches-per-zone'] = \
    {
        'default': {'0'},  # used to be '0 drop' in v9.11
        'validity': None,
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'server resource',
        'comment':
            """The maximum number of simultaneous iterative queries
            to any one domain that the server will permit before
            blocking new queries for data in or beneath that zone.
            This value should reflect how many fetches would
            normally be sent to any one zone in the time it would
            take to resolve them. It should be smaller than
            recursive-clients.
            
            When many clients simultaneously query for the same
            name and type, the clients will all be attached to
            the same fetch, up to the max-clients-per-query limit,
            and only one iterative query will be sent. However,
            when clients are simultaneously querying for different
            names or types, multiple queries will be sent and
            max-clients-per-query is not effective as a limit.
            
            Optionally, this value may be followed by the keyword
            drop or fail, indicating whether queries which exceed
            the fetch quota for a zone will be dropped with no
            response, or answered with SERVFAIL.
            
            The default is drop.
            
            If fetches-per-zone is set to zero, then there is no
            limit on the number of fetches per query and no queries
            will be dropped. The default is zero.
            The current list of active fetches can be dumped by
            running rndc recursing. The list includes the number of
            active fetches for each domain and the number of queries
            that have been passed or dropped as a result of the
            fetches-per-zone limit. (Note: these counters are not
            cumulative over time; whenever the number of active
            fetches for a domain drops to zero, the counter for that
            domain is deleted, and the next time a fetch is sent to
            that domain, it is recreated with the counters set to zero.)
            
            (Note: This option is only available when BIND is built
            with configure --enable-fetchlimit.)
            """,
    }

g_nc_keywords['file'] = \
    {
        'default': '.',
        'validity': {'function': 'path_name'},
        'found-in': {'zone'},
        # In 8.2, not found in ['zone']['type']['forward']
        # In 8.2, not found in ['zone']['type']['hint']
        'introduced': '8.2',
        'topic': 'zone data, redirect',
        'zone-type': {'master', 'slave', 'mirror', 'hint', 'stub', 'redirect', 'primary', 'secondary'},
        'comment': '',
    }

g_nc_keywords['files'] = \
    {
        'default': 'unlimited',  # changed from 'unlimited' in v9.12
        # change to 'unlimited' by v9.19
        'validity': {'regex': '(default|unlimited|[0-9]*)'},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system',
        'comment': """The maximum number of files the server may have
open concurrently. TODO 'zone' stop using 'files' around 9.15
The default is unlimited.""",
    }

g_nc_keywords['filter-aaaa'] = \
    {
        'default': None,  # Don't provide a default, that too is a compiler-directive
        'validity': {'function': 'address_match_nosemicolon'},
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'obsoleted': '9.14.0',
        'topic': 'filtering',
        'comment': """Specifies a list of addresses to which
filter-aaaa-on-v4 is applies.

The default is any.
Option 'filter-aaaa' activated at v9.12.0
""",
    }

g_nc_keywords['filter-aaaa-on-v4'] = \
    {
        'default': None,  # Don't provide a default, that too is a compiler-directive
        'validity': {'regex': r"(yes|no|break\-dnssec)"},
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'obsoleted': '9.14.0',
        'topic': 'filtering',
        'comment': """This option is only available when BIND 9 is
compiled with the --enable-filter-aaaa option on the
"configure" command line. It is intended to help the
transition from IPv4 to IPv6 by not giving IPv6 addresses
to DNS clients unless they have connections to the IPv6
Internet. This is not recommended unless absolutely
necessary. The default is no. The filter-aaaa-on-v4
option may also be specified in view statements to
override the global filter-aaaa-on-v4 option.

If yes, the DNS client is at an IPv4 address, in
filter-aaaa, and if the response does not include DNSSEC
signatures, then all AAAA records are deleted from the
response. This filtering applies to all responses and
not only authoritative responses.  If break-dnssec,
then AAAA records are deleted even when DNSSEC is
enabled. As suggested by the name, this makes the
response not verify, because the DNSSEC protocol is
designed detect deletions.

This mechanism can erroneously cause other servers to not
give AAAA records to their clients. A recursing server
with both IPv6 and IPv4 network connections that queries
an authoritative server using this mechanism via IPv4 will
be denied AAAA records even if its client is using IPv6.

This mechanism is applied to authoritative as well as
non-authoritative records. A client using IPv4 that is
not allowed recursion can erroneously be given AAAA
records because the server is not allowed to check for
A records.  Some AAAA records are given to IPv4 clients
in glue records. IPv4 clients that are servers can then
erroneously answer requests for AAAA records received
via IPv4.
Option 'filter-aaaa-on-v4' activated at v9.12.0
""",
    }

g_nc_keywords['filter-aaaa-on-v6'] = \
    {
        'default': None,
        'validity': {'regex': r"(yes|no|break\-dnssec)"},
        'found-in': {'options', 'view'},
        'introduced': '9.10.0',
        'obsoleted': '9.14.0',
        'topic': 'filtering',
        'comment': """Identical to filter-aaaa-on-v4, except it filters
AAAA responses to queries from IPv6 clients instead of
IPv4 clients. To filter all responses, set both options
to yes.  This option is only available when BIND 9 is
compiled with the --enable-filter-aaaa option on the
"configure" command line. It is intended to help the
transition from IPv4 to IPv6 by not giving IPv6
addresses to DNS clients unless they have connections
to the IPv6 Internet. This is not recommended unless
absolutely necessary. The default is no. The
filter-aaaa-on-v4 option may also be specified in
view statements to override the global
filter-aaaa-on-v4 option.

If yes, the DNS client is at an IPv4 address, in
filter-aaaa, and if the response does not include
DNSSEC signatures, then all AAAA records are deleted
from the response. This filtering applies to all
responses and not only authoritative responses.  If
break-dnssec, then AAAA records are deleted even when
DNSSEC is enabled. As suggested by the name, this
makes the response not verify, because the DNSSEC
protocol is designed detect deletions.

This mechanism can erroneously cause other servers to
not give AAAA records to their clients. A recursing
server with both IPv6 and IPv4 network connections
that queries an authoritative server using this
mechanism via IPv4 will be denied AAAA records even
if its client is using IPv6.

This mechanism is applied to authoritative as well as
non-authoritative records. A client using IPv4 that
is not allowed recursion can erroneously be given
AAAA records because the server is not allowed to
check for A records.  Some AAAA records are given to
IPv4 clients in glue records. IPv4 clients that are
servers can then erroneously answer requests for AAAA
records received via IPv4.
Option 'filter-aaaa-on-v6' activated at v9.12.0.
""",
    }

g_nc_keywords['flush-zones-on-shutdown'] = \
    {
        'default': "no",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'operating-system',
        'comment': """When the nameserver exits due receiving SIGTERM, flush or do not flush any pending
zone writes. The default is flush-zones-on-shutdown no.""",
    }

g_nc_keywords['forward'] = \
    {
        'default': 'first',
        'validity': {'regex': r'(first|only)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '8.1',
        'topic': 'forwarding',
        'zone-type': {'master', 'slave', 'stub', 'static-stub', 'forward', 'primary', 'secondary'},
        'comment': """This option is only meaningful if the forwarders
list is not empty. A value of first, the default, causes
the server to query the forwarders first - and if that
doesn't answer the question, the server will then look for
the answer itself. If only is specified, the server will
only query the forwarders.  TODO: when setting up
2-process Split-Horizon DNS, this should be 'only'""",
    }

g_nc_keywords['forwarders'] = \
    {
        'default': {'aml': 'none'},
        'validity': {'function': 'in_addr_list'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.2',  # Intro in 4.8, 8.1, not yet back in 9.0
        'topic': 'forwarding, dscp',
        'zone-type': {'master', 'slave', 'stub', 'static-stub', 'forward', 'primary', 'secondary'},
        'comment': """Specifies the IP addresses to be used for forwarding.
The default is the empty list (no forwarding).  Forwarding
can also be configured on a per-domain basis, allowing for
the global forwarding options to be overridden in a variety
of ways. You can set particular domains to use different
forwarders, or have a different forward only/first
behavior, or not forward at all, see Section 6.2.""",
    }

g_nc_keywords['geoip-directory'] = \
    {
        'default': '',
        'validity': {'function': 'path_name'},
        'found-in': {'options'},
        'introduced': '9.10.0',
        'topic': 'operating-system, geoip',
        'comment': """Specifies the directory containing GeoIP .dat
database files for GeoIP initialization. By default,
this option is unset and the GeoIP support will use
libGeoIP's built-in directory.  (For details, see
Section 6.2 about the geoip ACL.)""",
    }

g_nc_keywords['geoip-use-ecs'] = \
    {
        'default': '',
        'validity': {'function': 'path_name'},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'obsoleted': '9.14.0',
        'topic': 'operating-system, geoip, inert',
        'comment': '',
    }

g_nc_keywords['glue-cache'] = \
    {
        'default': 'yes',
        'validity': {'regex': '(yes|no)'},
        'found-in': {'options', 'view'},  # 'view' added in 9.12?
        'introduced': '9.12',
        'deprecated': '9.17',
        'topic': 'glue, cache, caching',
        'comment': '',
    }

g_nc_keywords['has-old-clients'] = \
    {
        'default': 'no',
        'validity': {'regex': '(yes|no)'},
        'found-in': {'options'},
        'introduced': '8.2',
        'obsoleted': '9.7.0',
        'topic': 'operating-system, geoip, inert',
        'comment': """This option was incorrectly implemented in BIND 8,
and is ignored by BIND 9. To achieve the intended
effect of has-old-clients yes, specify the two
separate options authnxdomain yes and rfc2308-type1
no instead.""",
    }

g_nc_keywords['heartbeat-interval'] = \
    {
        'default': '60',
        'validity': {'range': {0, 40320}},
        'unit': 'minute',
        'found-in': {'options'},
        'introduced': '8.2',
        'topic': 'zone, operating-system, server resource, periodic task',
        'comment':
            """The server will perform zone maintenance tasks for all
            zones marked as dialup whenever this interval expires.
            The default is 60 minutes.
            Reasonable values are up to 1 day (1440 minutes).
            The maximum value is 28 days (40320 minutes).
            If set to 0, no zone maintenance for these zones will occur.""",
    }

g_nc_keywords['host-statistics'] = \
    {
        'default': '0',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options'},
        'introduced': '8.2',
        'obsoleted': '9.14',
        'topic': 'operating-system, not implemented, inert',
        'comment': """In BIND 8, this enables keeping of statistics for
every host that the name server interacts with.
Not implemented in BIND 9.""",
    }

g_nc_keywords['host-statistics-max'] = \
    {
        'default': '0',
        'validity': None,
        'found-in': {'options'},
        'introduced': '8.3',
        'obsoleted': '9.14',
        'topic': 'operating-system, server resource, not implemented',
        'comment': """In BIND 8, specifies the maximum number of host
statistics entries to be kept. Not implemented
in BIND 9.""",
    }

g_nc_keywords['hostname'] = \
    {
        'default': '',
        'validity': {'options': 'none',
                     'regex': r'[A-Za-z0-9\-_]{1-64}(\.[A-Za-z0-9\-_]{1-64})*"',
                     },
        'found-in': {'options', 'tls'},  # dropped 'masters' in v9.???
        'introduced': '8.3',
        'topic': 'CHAOS, server info',
        'comment': """The hostname the server should report via a query of the
name hostname.bind with type TXT, class CHAOS.
This defaults to the hostname of the machine hosting the
name server as found by the gethostname() function. The
primary purpose of such queries is to identify which of a
group of anycast servers is actually answering your queries.

Specifying hostname none; disables processing of the queries."""
    }

g_nc_keywords['http-listener-clients'] = \
    {
        'default': 300,
        'validity': {'range': {1, 65535}},
        'found-in': {'options'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': '',
    }

g_nc_keywords['http-port'] = \
    {
        'default': 80,
        'validity': {'range': {1, 65535}},
        'found-in': {'options'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': """An IP port number. The number is limited to 1 
through 65535, with values below 1024 typically 
restricted to use by processes running as root. In 
some cases, an asterisk (*) character can be used as 
a placeholder to select a random high-numbered port.""",
    }

g_nc_keywords['http-streams-per-connection'] = \
    {
        'default': 100,
        'validity': {'range': {1, 65535}},
        'found-in': {'options'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': '',
    }

g_nc_keywords['https-port'] = \
    {
        'default': 443,
        'validity': {'range': {1, 65535}},
        'found-in': {'options'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': """An IP port number. The number is limited to 1 
through 65535, with values below 1024 typically 
restricted to use by processes running as root. 
In some cases, an asterisk (*) character can be used 
as a placeholder to select a random high-numbered port.""",
    }

g_nc_keywords['in-view'] = \
    {
        'default': None,
        'validity': {'function': 'valid_view_name'},
        'found-in': {'zone'},
        'zone-type': {'in-view'},
        'introduced': '9.10.0',
        'topic': 'zone, view',
        'comment': """
Only valid within a zone clause.
Allows a zone clause within one view to be used by another view.

The view-name must refer to a valid view which contains a zone of the same
name and the view containing the zone must have been previously defined
(only backward references to views are allowed, not forward references).
The in-view zone uses all the statements in the previously defined zone
clause and thus is particularly useful if you defined a shed-load of
stuff in the previous zone clause. Only forward and forwarders
statements are allowed in in-view zone clauses.
""",
    }

g_nc_keywords['inet'] = \
    {
        'default': None,
        'validity': {'function': 'inet'},
        'occurs-multiple-times': False,
        'topblock': False,
        'found-in': {'controls', 'statistics-channels'},  # added to 'statistics-channels' in v9.5
        'introduced': '8.1',
        'topic': 'Unix socket, IPC',
        'comment': ''
    }

g_nc_keywords['inline-signing'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'zone'},  # removed 'options', 'view' in 9.19.0
        'introduced': '9.9.0',
        'topic': 'DNSSEC',
        'zone-type': {'primary', 'secondary', 'master', 'slave'},
        'comment':
            """If yes, this enables "bump-in-the-wire" signing
of a zone, where an unsigned zone is transferred in or
loaded from disk and a signed version of the zone is
served, with possibly a different serial number.

When set to "yes", this option will sign transferred
unsigned zones, and unsigned zone from file.  This is
also no longer needed when KASP is introduced because
when setting a `dnssec-policy` for a secondary zone
or a zone with zone file, this indicates that
`inline-signing` is desired.

This behavior is disabled by default.

Added to 'options' and 'view' section in v9.9.0.""",
    }

g_nc_keywords['interface-interval'] = \
    {
        'default': '60',
        'validity': {'range': {0, 40320}},
        'unit': 'minute',
        'found-in': {'options'},
        'introduced': '8.2',
        'topic': 'operating-system, server resource, periodic interval',
        'comment':
            """The server will scan the network interface list every
interface-interval minutes. The default is 60 minutes.
The maximum value is 28 days (40320 minutes).
If set to 0, interface scanning will only occur when the
configuration file is loaded. After the scan, the server
will begin listening for queries on any newly discovered
interfaces (provided they are allowed by the listen-on
configuration), and will stop listening on interfaces
that have gone away.""",
    }

g_nc_keywords['ipv4only-contact'] = \
    {
        'default': None,
        'validity': {'string'},
        'found-in': {'options', 'view'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': ''
    }

g_nc_keywords['ipv4only-enable'] = \
    {
        'default': 'no',
        'validity': {'function': 'boolean'},
        'found-in': {'options', 'view'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': ''
    }

g_nc_keywords['ipv4only-server'] = \
    {
        'default': None,
        'validity': {'string'},
        'found-in': {'options', 'view'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': ''
    }
g_nc_keywords['ixfr-base'] = \
    {
        'default': None,
        'validity': {'regex': r'\s'},  # filespec (w/o '/')
        'found-in': {'view', 'zone'},
        'introduced': '8.0',
        'obsoleted': '9.14.0',
        'topic': 'transfer, IXFR',
        'zone-type': {'master', 'primary'},
        'comment': """Was used in Bind 8 to specify the name of the
transaction log (journal) file for dynamic update and
IXFR.  Bind9 ignores this option and constructs the
name of the journal file by appending ".jnl" to the
name of the zone file.""",
    }

g_nc_keywords['ixfr-from-differences'] = \
    {
        'default': 'primary',  # changed from 'yes' in v9.13
        'validity': {'regex': r'(primary|master|yes|no|slave|secondary)'},
        'found-in': {'options', 'view'},
        'introduced': '9.5.0',
        'topic': 'transfer, IXFR, journal',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment':
            """When yes and the server loads a new version of a master
zone from its zone file or receives a new version of a
slave file via zone transfer, it will compare the new
version to the previous one and calculate a set of
differences. The differences are then logged in the zone's
journal file such that the changes can be transmitted to
downstream slaves as an incremental zone transfer.
By allowing incremental zone transfers to be used for
non-dynamic zones, this option saves bandwidth at the
expense of increased CPU and memory consumption at
the master.
In particular, if the new version of a zone is
completely different from the previous one, the set of
differences will be of a size comparable to the combined
size of the old and new zone version, and the server will
need to temporarily allocate memory to hold this complete
difference set.
ixfr-from-differences also accepts master and slave at
the view and options levels which causes
ixfr-from-differences to be enabled for all master or
slave zones respectively. It is off by default.""",
    }

g_nc_keywords['ixfr-from-differences'] = \
    {
        'default': 'yes',
        'validity': {'options': r'(primaries|secondaries|masters|slaves)',
                     'views': 'boolean'},
        'found-in': {'options', 'view'},  # only 'zone' got dropped at v9.18.0 after initial intro
        'introduced': '9.3.0',
        'topic': 'IXFR, transfer',
        'comment': '',
    }

g_nc_keywords['ixfr-tmp-file'] = \
    {
        'default': '',
        'validity': {'function': 'quoted_filespec'},
        'found-in': {'view'},
        'introduced': '9.0',
        'obsoleted': '9.14',
        'topic': 'inert, IXFR, transfer',
        'comment': '',
    }

g_nc_keywords['journal'] = \
    {
        'default': None,
        'validity': {'function': "path_name"},
        'found-in': {'zone'},
        'introduced': '9.3.0',
        'topic': 'journal, zone',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment': '',
    }

g_nc_keywords['keep-response-order'] = \
    {
        'default': {0: {'addr': 'none'}},
        'validity': {'function': "address_match_list"},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'obsoleted': '9.19.0',
        'topic': 'access control',
        'comment':
            """
            Specifies a list of addresses to which the server will
            send responses to TCP queries in the same order in
            which they were received. This disables the processing
            of TCP queries in parallel.  The default is none.
            """,
    }

g_nc_keywords['key-directory'] = \
    {
        'default': '.',
        'validity': {'function': 'path_name'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.3.0',
        'topic': 'operating-system, dnssec',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment':
            """is a quoted string defining the absolute path, for
example, "/var/named/keys" where the keys used in the
dynamic update of secure zones may be found.  Only
required if this directory is different from that
defined by a directory option.

`key-directory` is where the DNSKEY key files can be found.

This statement may only be used in a global
options clause.""",
    }

g_nc_keywords['key-file'] = \
    {
        'default': None,
        'validity': {'function': 'quoted_filepath'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'DoH, TLS, HTTPS',
        'comment': '',
    }

g_nc_keywords['keys'] = \
    {
        'default': None,
        'validity': {'function': 'key_name'},
        'found-in': {'server', 'dnssec-policy'},
        'introduced': '9.2',
        'topic': 'transfer, DNSSEC, key',
        'occurs-multiple-times': True,
        'comment': """The keys clause is used to identify a keyname defined
by the key statement, to be used for transaction
security when talking to the remote server. The key
statement must come before the server statement that
references it. When a request is sent to the remote
server, a request signature will be generated using
the key specified here and appended to the message.
A request originating from the remote server is not
required to be signed by this key."""
    }

g_nc_keywords['lame-ttl'] = \
    {
        'default': 0,  # changed from 600 at v9.17.4
        'validity': {'range': {0, 1800}},
        'unit': 'second',
        'found-in': {'options', 'view'},
        'introduced': '8.2',
        'topic': 'tuning, cache, caching',
        'comment': """Sets the number of seconds to cache a lame server
indication. 0 disables caching. (This is NOT
recommended.)
The default is 600 (10 minutes) and the maximum value
is 1800 (30 minutes).

Lame-ttl also controls the amount of time DNSSEC
validation failures are cached. There is a minimum
of 30 seconds applied to bad cache entries if the
lame-ttl is set to less than 30 seconds.""",
    }

g_nc_keywords['lifetime'] = \
    {
        'default': 'unlimited',
        'validity': {'function': 'iso8601_time_duration',
                     'regex': '(unlimited)'},
        'unit': 'second_unless_stated',
        'introduced': '9.17.0',
        'found-in': {'keys'},
        'topic': 'dnssec, dnssec-policy',
        'comment': """
The lifetime parameter specifies how long a key may be
used before rolling over.
The default is 1 hour (3660 seconds).
""",
    }

g_nc_keywords['listen-on'] = \
    {
        'default': {'port': 53,
                    0: {'addr': 'any', 'port': "53"}},
        'validity': {'function': "address_match_list"},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'interface, DSCP',
        'comment':
            """The interfaces and ports that the server will answer
queries from may be specified using the listen-on
option. listen-on takes an optional port and an
address_match_nosemicolon of IPv4 addresses. (IPv6
addresses are ignored, with a logged warning.)
The server will listen on all interfaces allowed by the
address match list. If a port is not specified, port 53
will be used.
Multiple listen-on statements are allowed. For example,

listen-on { 5.6.7.8; };
listen-on port 1234 { !1.2.3.4; 1.2/16; };

will enable the name server on port 53 for the IP
address 5.6.7.8, and on port 1234 of an address
on the machine in net 1.2 that is not 1.2.3.4.
If no listen-on is specified, the server will listen on
port 53 on all IPv4 interfaces.""",
    }

g_nc_keywords['listen-on-v6'] = \
    {
        'default': {0: {'addr': 'any'}},
        'validity': {'function': "address_match_list"},
        'found-in': {'options'},
        'introduced': '9.2',
        'topic': 'IPv6, interface, DSCP',
        'comment': """If no listen-on is specified, the server will
listen on port 53 on all IPv4 interfaces.  The
listen-on-v6 option is used to specify the interfaces
and the ports on which the server will listen for
incoming queries sent using IPv6. If not specified,
the server will listen on port 53 on all IPv6
interfaces.
When { any; } is specified as the
address_match_nosemicolon for the listen-on-v6 option,
the server does not bind a separate socket to each
IPv6 interface address as it does for IPv4 if the
operating system has enough API support for IPv6
(specifically if it conforms to RFC 3493 and RFC 3542).
Instead, it listens on the IPv6 wildcard address. If
the system only has incomplete API support for IPv6,
however, the behavior is the same as that for IPv4.

A list of particular IPv6 addresses can also be
specified, in which case the server listens on a
separate socket for each specified address,
regardless of whether the desired API is supported by
the system. IPv4 addresses specified in listen-on-v6
will be ignored, with a logged warning.  Multiple
listen-on-v6 options can be used. For example,
listen-on-v6 { any; };
listen-on-v6 port 1234 { !2001:db8::/32; any; };
will enable the name server on port 53 for any IPv6
addresses (with a single wildcard socket), and on
port 1234 of IPv6 addresses that is not in the
prefix 2001:db8::/32 (with separate sockets for each
matched address.)

To make the server not listen on any IPv6 address, use
listen-on-v6 { none; };""",
    }

g_nc_keywords['listener-clients'] = \
    {
        'default': 300,
        'validity': {'range': {1, 65535}},
        'found-in': {'http'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': 'seems very similiar to \'http-listener-clients\'',
    }

g_nc_keywords['lmdb-mapsize'] = \
    {
        'default': '32M',
        'validity': {'function': "sizeval"},
        'found-in': {'options', 'view'},
        'introduced': '9.12.0',
        'topic': 'operating-system, database',
        'comment': '',
    }

g_nc_keywords['lock-file'] = \
    {
        'default': '/run/named/named.lock',
        'validity': {'function': "path_name"},
        'found-in': {'options'},
        'introduced': '9.11.0',
        'topic': 'operating-system',
        'comment': """""",
    }

g_nc_keywords['maintain-ixfr-base'] = \
    {
        'default': "yes",  # was 'no' in 8.1
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '8.2',
        'obsoleted': '9.7.0',  # ignored since 9.0
        'topic': 'inert, transfer, IXFR',
        'zone-type': {'primary', 'master'},
        'comment': """maintain-ixfr-base
This option is obsolete. It was used in BIND 8 to
determine whether a transaction log was kept for
Incremental Zone Transfer. BIND 9 maintains a
transaction log whenever possible.  If you need to
disable outgoing incremental zone transfers,
use provide-ixfr no.""",
    }

g_nc_keywords['managed-keys-directory'] = \
    {
        'default': "\".\"",
        'validity': {'function': "managed_key_path_name_quotestring"},
        'found-in': {'options'},
        'introduced': '9.8.0',
        'topic': 'operating-system, dnssec',
        'comment': """Specifies the directory in which to store the files
that track managed DNSSEC keys.
By default, this is the working directory.

If named is not configured to use views, then managed
keys for the server will be tracked in a single file
called managed-keys.bind.

Otherwise, managed keys will be tracked in separate
files, one file per view; each file name will be the
SHA256 hash of the view name, followed by the
extension .mkeys.""",
    }

g_nc_keywords['masterfile-format'] = \
    {
        'default': 'map',  # change from 'text' in v9.12
        'validity': {'regex': r'(map|text|raw)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'zone file, tuning',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'redirect', 'primary', 'secondary'},
        'comment': """Specifies the file format of zone files (see Section
6.3.7).  The default value is text, which is the
standard textual representation, except for slave
zones, in which the default value is raw. Files in
other formats than text are typically expected to be
generated by the named- compilezone tool, or dumped
by named.

Note that when a zone file in a different format than
text is loaded, named may omit some of the checks
which would be performed for a file in the text
format. In particular, check-names checks do not
apply for the raw format. This means a zone file in
the raw format must be generated with the same check
level as that specified in the named configuration
file. Also, map format files are loaded directly into
memory via memory mapping, with only minimal checking.

This statement sets the masterfile-format for all
zones, but can be overridden on a per-zone or
per-view basis by including a masterfile-format
statement within the zone or view block in the
configuration file.  Note that zones using 'map'
cannot be used as policy zones.
""",
    }

g_nc_keywords['masterfile-style'] = \
    {
        'default': 'full',
        'validity': {'regex': r'(full|relative)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.11.0',
        'topic': 'zone file, tuning, master file',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'redirect', 'primary', 'secondary'},
        'comment': 'slave, secondary',
    }

# This is 'zone' 'masters' option which is
# not to be confused with top-level 'masters' statement.
g_nc_keywords['masters'] = \
    {
        'default': None,
        'validity': {'function': 'masters_zone'},
        'found-in': {'zone'},
        'introduced': '9.0.0',
        'topic': 'masters',
        'zone-type': {'slave', 'mirror', 'stub', 'redirect', 'secondary'},
        'occurs-multiple-times': False,
        'topblock': False,
        'comment': 'slave, secondary',
    }

g_nc_keywords['match-clients'] = \
    {
        'default': {0: {'addr': 'any'}},
        'validity': {'function': 'address_match_list'},
        'found-in': {'view'},
        'introduced': '9.3.0',
        'topic': 'content filtering',
        'comment': '',
    }

g_nc_keywords['match-destination'] = \
    {
        'default': {0: {'addr': 'any'}},
        'validity': {'function': 'address_match_list'},
        'found-in': {'view'},
        'introduced': '9.3.0',
        'topic': 'content filtering',
        'comment': '',
    }

g_nc_keywords['match-mapped-addresses'] = \
    {
        'default': "no",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.2',
        'topic': 'operating-system',
        'comment': """If yes, then an IPv4-mapped IPv6 address will match
any address match list entries that match the
corresponding IPv4 address.  This option was
introduced to work around a kernel quirk in some
operating systems that causes IPv4 TCP connections,
such as zone transfers, to be accepted on an IPv6
socket using mapped addresses. This caused address
match lists designed for IPv4 to fail to match.
However, named now solves this problem internally.
The use of this option is discouraged.""",
    }

g_nc_keywords['match-recursive-only'] = \
    {
        'default': 'no',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'view'},
        'introduced': '9.3.0',
        'topic': 'recursive, filter',
        'comment': '',
    }

g_nc_keywords['max-acache-size'] = \
    {
        'default': "16M",
        'validity': {'function': "size_spec"},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'obsoleted': '9.12',
        'topic': 'additional section cache, caching',
        'comment': """The maximum amount of memory in bytes to use for the
server's acache. When the amount of data in the acache
reaches this limit, the server will clean more aggressively
so that the limit is not exceeded. In a server with
multiple views, the limit applies separately to the
acache of each view.
The default is 16M.""",
    }

g_nc_keywords['max-cache-size'] = \
    {
        'default': '90%',  # change to 90% at v9.19; from 'unlimited' in v9.12
        'validity': {'size': "size_spec",
                     'function': "percentage",
                     'regex': '(default|unlimited)'},
        'unit': 'memory_byte',
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',
        'topic': 'server resource, operating system, cache, caching',
        'comment':
            """The maximum amount of memory to use for the server's
cache, in bytes. When the amount of data in the cache
reaches this limit, the server will cause records to
expire prematurely based on an LRU based strategy so that
the limit is not exceeded. The keyword unlimited, or the
value 0, will place no limit on cache size; records will
be purged from the cache only when their TTLs expire.
Any positive values less than 2MB will be ignored and
reset to 2MB. In a server with multiple views, the limit
applies separately to the cache of each view.

The default is unlimited.""",
    }

g_nc_keywords['max-cache-ttl'] = \
    {
        'default': '604800',
        'validity': {'function': 'iso8601_time_duration'},
        'unit': 'second_unless_stated',
        'found-in': {'options', 'view'},
        'introduced': '9.0.0',
        'topic': 'server resource, tuning, cache, caching',
        'comment': """Sets the maximum time for which the server will cache
ordinary (positive) answers.  The default is one
week (7 days).  A value of zero may cause all queries
to return SERVFAIL, because of lost caches of
intermediate RRsets (such as NS and glue AAAA/A
records) in the resolution process.
Units in seconds.""",
    }

g_nc_keywords['max-clients-per-query'] = \
    {
        'default': 100,
        'validity': {'range': (0, 2147483647)},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'DNS, server resource',
        'comment':
            """These set the initial value (minimum) and maximum
number of recursive simultaneous clients for any given
query (<qname,qtype,qclass>) that the server will accept
before dropping additional clients. named will attempt
to self tune this value and changes will be logged.
The default values are 10 and 100.
This value should reflect how many queries come in for a
given name in the time it takes to resolve that name. If
the number of queries exceed this value, named will
assume that it is dealing with a non-responsive zone and
will drop additional queries. If it gets a response after
dropping queries, it will raise the estimate.
The estimate will then be lowered in 20 minutes if it has
remained unchanged.
If clients-per-query is set to zero, then there is no
limit on the number of clients per query and no queries
will be dropped.
If max-clients-per-query is set to zero, then there is
no upper bound other than imposed by recursive-clients.""",
    }

g_nc_keywords['max-ixfr-log-size'] = \
    {
        'default': "default",  # change from 'unlimited' in v9.12
        'validity': {'range': (0, 2147483647),
                     'regex': '(unlimited|default)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.0.0',
        'deprecated': '9.1.0',
        'obsoleted': '9.1.0',
        'ancient': '9.14.0',
        'topic': 'transfer, IXFR, server resource',
        'zone-type': {'master'},
        'comment':
            """This option is obsolete; it is accepted and ignored
for BIND 8 compatibility. The option max-journal-size
performs a similar function in BIND 9.""",
    }

g_nc_keywords['max-ixfr-ratio'] = \
    {
        'default': "default",
        'validity': {'range': (0, 100),
                     'regex': '(unlimited|percentage)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.16.0',
        'topic': 'transfer, IXFR, performance',
        'zone-type': {'master', 'primary', 'mirror', 'slave', 'secondary'},
        'comment':
            """This sets the size threshold (expressed as a
percentage of the size of the full zone) beyond which
named chooses to use an AXFR response rather than
IXFR when answering zone transfer requests.
            
See Incremental Zone Transfers (IXFR).
            
The minimum value is 1%.
            
The keyword 'unlimited' disables ratio checking and
allows IXFRs of any size.
            
The default is 100%.
            
When a secondary server receives a zone via AXFR, it 
creates a new copy of the zone database and then swaps 
it into place; during the loading process, queries 
continue to be served from the old database with no 
interference. When receiving a zone via IXFR, however, 
changes are applied to the running zone, which may 
degrade query performance during the transfer. If a 
server receiving an IXFR request determines that the 
response size would be similar in size to an AXFR 
response, it may wish to send AXFR instead. The 
threshold at which this determination is made can be 
configured using the max-ixfr-ratio option.""",
    }

g_nc_keywords['max-journal-size'] = \
    {
        'default': 'default',
        'validity': {'function': 'size_spec'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.3.0',
        'topic': 'journal, server resource, file space, disk space',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment':
            """Sets a maximum size for each journal file (see
            Section 4.2). When the journal file approaches the
            specified size, some of the oldest transactions in the
            journal will be automatically removed.
            
            The largest permitted value is 2 gigabytes.
            
            The default is unlimited, which also means 2 gigabytes.
            
            This may also be set on a per-zone basis.""",
    }

g_nc_keywords['max-ncache-ttl'] = \
    {
        'default': '10800',  # 3 hours
        'validity': {'function': "iso8601_time_duration",
                     'range': {0, 604800},
                     'regex': '(default|unlimited)'},
        'unit': 'second_unless_declared',
        'found-in': {'options', 'view'},  # removed 'zone' in 9.17?
        'introduced': '8.2',
        'topic': 'server resource, tuning, cache, caching',
        'comment': """To reduce network traffic and increase performance, the server stores
negative answers. max-ncache-ttl is used to set a maximum retention time for these
answers in the server in seconds.
The default max-ncache-ttl is 10800 seconds (3 hours).
max-ncache-ttl cannot exceed 7 days and will be silently truncated to 7 days if set to a greater value.
""",
    }

g_nc_keywords['max-records'] = \
    {
        'default': 0,  # 0=unlimited
        'validity': {'range': {0, 32767}},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.12',
        'topic': 'DNS, server resource',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'static-stub', 'redirect', 'primary', 'secondary'},
        'comment':
            """The maximum number of records permitted in a zone.

The default is zero which means unlimited.""",
    }

g_nc_keywords['max-recursion-depth'] = \
    {
        'default': 7,
        'validity': {'range': {0, 1024}},
        'unit': 'level',
        'found-in': {'options', 'view'},
        'introduced': '9.9.0',  # effective on 9.11?
        'topic': 'tuning',
        'comment': """Sets the maximum number of levels of recursion that are
permitted at any one time while servicing a recursive query.
Resolving a name may require looking up a name server address,
which in turn requires resolving another name, etc; if the
number of indirections exceeds this value, the recursive
query is terminated and returns SERVFAIL. The default is 7.""",
    }

g_nc_keywords['max-recursion-queries'] = \
    {
        'default': 100,  # was 75 in v9.11
        'validity': {'range': {0, 1024}},
        'unit': 'queries_per_recursion',
        'found-in': {'options', 'view'},
        'introduced': '9.9.0',
        'topic': 'tuning',
        'comment': """Sets the maximum number of iterative queries that may be
sent while servicing a recursive query. If more queries are
sent, the recursive query is terminated and returns
SERVFAIL.
Queries to look up top level comains such as "com" and "net"
and the DNS root zone are exempt from this limitation.
The default is 75.""",
    }

g_nc_keywords['max-refresh-time'] = \
    {
        'default': '4w',
        'validity': {'min': '1s', 'max': '24w'},
        'unit': 'iso8601_time_duration',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.1',
        'topic': 'tuning, obsoleted, inert',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},  # stub added 9.11
        'comment': """These options control the server's behavior on refreshing
a zone (querying for SOA changes) or retrying failed transfers.
Usually the SOA values for the zone are used, but these values are
set by the master, giving slave server administrators little control
over their contents.
NOTE: Not implemented in BIND 9.
These options allow the administrator to set a minimum and maximum
refresh and retry time either per-zone, per-view, or globally.
These options are valid for slave and stub zones, and clamp the
SOA refresh and retry times to the specified values.
The following defaults apply. min-refresh-time 300 seconds,
max-refresh-time 2419200 seconds (4 weeks),
min-retry-time 500 seconds, and
max-retry-time 1209600 seconds (2 weeks).""",
    }

g_nc_keywords['max-retry-time'] = \
    {
        'default': '2w',
        'validity': {'min': '1s', 'max': '24w'},
        'unit': 'iso8601_time_duration',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.1',
        'topic': 'tuning, obsoleted, inert',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment': """These options control the server's behavior on
refreshing a zone (querying for SOA changes) or
retrying failed transfers.  Usually the SOA values
for the zone are used, but these values are set by
the master, giving slave server administrators little
control over their contents.
NOTE: Not implemented in BIND 9.
These options allow the administrator to set a
minimum and maximum refresh and retry time either
per-zone, per-view, or globally.  These options are
valid for slave and stub zones, and clamp the SOA
refresh and retry times to the specified values.
The following defaults apply. min-refresh-time 300
seconds, max-refresh-time 2419200 seconds (4 weeks),
min-retry-time 500 seconds, and max-retry-time
1209600 seconds (2 weeks).""",
    }

g_nc_keywords['max-rsa-exponent-size'] = \
    {
        'default': 0,  # no limit
        'validity': {'range': {35, 4096},
                     'string': '0'},
        'unit': 'bits',
        'found-in': {'options'},
        'introduced': '9.10',  # changed to '0'/no-limit in v9.6
        'topic': 'RSA, dnssec, tuning',
        'comment': """The maximum RSA exponent size, in bits, that will be
accepted when validating.
Valid values are 35 to 4096 bits.
The default zero (0) is also accepted and is equivalent to 4096.""",
    }

g_nc_keywords['max-stale-ttl'] = \
    {
        'default': '86400',  # 1 day; was '1w' in v9.12
        'validity': {'function': 'iso8601_time_duration'},
        'unit': 'second_unless_stated',
        'found-in': {'options', 'view'},
        'introduced': '9.12',
        'topic': 'DNS, tuning',
        'comment': '',
    }

g_nc_keywords['max-transfer-idle-in'] = \
    {
        'default': 60,
        'validity': {'range': {0, 40320},
                     'function': 'time_spec'},
        'unit': 'minute',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.0.0',
        'topic': 'transfer',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment':
            """Inbound zone transfers making no progress in this many
            minutes will be terminated. The default is 60 minutes
            (1 hour). The maximum value is 28 days (40320 minutes).""",
    }

g_nc_keywords['max-transfer-idle-out'] = \
    {
        'default': '60',
        'validity': {'range': {0, 40320},
                     'function': 'time_spec'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.0.0',
        'topic': 'transfer',
        'zone-type': {'master', 'slave', 'mirror', 'secured', 'primary', 'secondary'},
        'comment':
            """Outbound zone transfers making no progress in this many
minutes will be terminated.  The default is 60 minutes
(1 hour). The maximum value is 28 days (40320 minutes).""",
    }

g_nc_keywords['max-transfer-time-in'] = \
    {
        'default': '120',
        'validity': {'range': {0, 40320},
                     'function': 'time_spec'},
        'unit': 'minute',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '8.1',
        'topic': 'transfer',
        'zone-type': {'slave', 'mirror', 'stub', 'secured', 'secondary'},
        'comment':
            """Inbound zone transfers running longer than this many
minutes will be terminated. The default is 120 minutes
(2 hours). The maximum value is 28 days (40320 minutes).""",
    }

g_nc_keywords['max-transfer-time-out'] = \
    {
        'default': "120",
        'validity': {'range': {0, 40320},
                     'function': 'time_spec'},
        'unit': 'minute',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.0.0',
        'topic': 'transfer',
        'zone-type': {'master', 'slave', 'mirror', 'secured', 'primary', 'secondary'},
        'comment':
            """Outbound zone transfers running longer than this many
minutes will be terminated. The default is 120 minutes
(2 hours). The maximum value is 28 days (40320 minutes).""",
    }

g_nc_keywords['max-udp-size'] = \
    {
        'default': '1232',  # changed from 4096 at v9.16
        'validity': {'range': {512, 4096}},
        'unit': 'udp_buffer_byte_size',
        'found-in': {'options', 'view', 'server'},
        'introduced': '9.4.0',
        'topic': 'tuning, server, EDNS, UDP, transport layer',
        'comment': """Sets the maximum EDNS UDP message size named will send in bytes.
Valid values are 512 to 4096 (values outside this range will be
silently adjusted to the nearest value within it).

The default value is 1232.

This value applies to responses sent by a server; to set the
advertised buffer size in queries, see edns-udp-size.

The usual reason for setting max-udp-size to a non-default
value is to get UDP answers to pass through broken firewalls
that block fragmented packets and/or block UDP packets that are
greater than 512 bytes. This is independent of the advertised
receive buffer (edns-udp-size).

Setting this to a low value will encourage additional TCP
traffic to the nameserver.""",
    }

g_nc_keywords['max-zone-ttl'] = \
    {
        'default': "unlimited",
        'validity': {'regex': r"(unlimited|([0-9]{1,5})"},
        'found-in': {'options', 'view', 'zone', 'dnssec-policy'},
        'unit': 'second',
        'introduced': '9.10.0',
        'topic': 'zone, dnssec, cache, caching',
        'zone-type': {'master', 'primary', 'redirect'},
        'comment': """Specifies a maximum permissible TTL value. '
When loading a zone file using a masterfile-format of
text or raw, any record encountered with a TTL higher
than maxzone-ttl will cause the zone to be rejected.
This is useful in DNSSEC-signed zones because when
rolling to a new DNSKEY, the old key needs to remain
available until RRSIG records have expired from caches
. The max-zone-ttl option guarantees that the largest
TTL in the zone will be no higher the set value.

This will cap all TTLs in a zone file to the
specified value. Although this option may be used for
non-DNSSEC zones, it is really only useful for
DNSSEC-signed zones because when performing key
rollovers the timing depends on the largest TTL in
the zone.  The value set in the `dnssec-policy`
statement will override the existing `max-zone-ttl`
value.

NOTE: Because map-format files load directly into
memory, this option cannot be used with them.

The default value is unlimited.
A max-zone-ttl of zero is treated as unlimited.""",
    }

g_nc_keywords['memstatistics'] = \
    {
        'default': "no",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.5.0',
        'topic': 'operating-system',
        'comment': """Write memory statistics to the file specified by memstatistics-file at exit. The default is no
unless '-m record' is specified on the command line in which case it is yes.""",
    }

g_nc_keywords['memstatistics-file'] = \
    {
        'default': '"named.memstats"',
        'validity': {'function': "quoted_path_name"},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system',
        'comment': """The pathname of the file the server writes memory usage statistics to on exit.

If not specified, the default is named.memstats.""",
    }

g_nc_keywords['message-compression'] = \
    {
        'default': 'yes',  # was 'no' before v9.12
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'query, compression, answer',
        'comment': '',
    }

g_nc_keywords['min-cache-ttl'] = \
    {
        'default': 0,
        'validity': {'range': {0, 90}},
        'unit': 'second',  # code comment says 'hour' for a unit (error?)
        'found-in': {'options', 'view'},
        'introduced': '9.14',
        'topic': 'tuning, cache, caching',
        'comment': '',
    }

g_nc_keywords['min-ncache-ttl'] = \
    {
        'default': 0,
        'validity': {'range': {0, 90}},
        'unit': 'second',
        'found-in': {'options', 'view'},
        'introduced': '9.14',
        'topic': 'tuning, cache, caching',
        'comment': '',
    }

g_nc_keywords['min-refresh-time'] = \
    {
        'default': 300,
        'validity': {'min': '1s', 'max': '24w'},
        'unit': 'iso8601_time_duration',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.1',
        'topic': 'tuning, inert',
        'zone-type': {'slave', 'mirror', 'stub', 'zone', 'secondary'},
        'comment': """These options control the server's behavior on refreshing
a zone (querying for SOA changes) or retrying failed transfers.
Usually the SOA values for the zone are used, but these values are
set by the master, giving slave server administrators little control
over their contents.
These options allow the administrator to set a minimum and maximum
refresh and retry time either per-zone, per-view, or globally.
These options are valid for slave and stub zones, and clamp the
SOA refresh and retry times to the specified values.
The following defaults apply. min-refresh-time 300 seconds,
max-refresh-time 2419200 seconds (4 weeks),
min-retry-time 500 seconds, and
max-retry-time 1209600 seconds (2 weeks).""",
    }

g_nc_keywords['min-retry-time'] = \
    {
        'default': '500',
        'validity': {'min': '1s', 'max': '24w'},
        'unit': 'iso8601_time_duration',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.1',
        'topic': 'tuning, inert',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment': """These options control the server's behavior on
refreshing a zone (querying for SOA changes) or
retrying failed transfers.  Usually the SOA values
for the zone are used, but these values are set by
the master, giving slave server administrators little
control over their contents.
These options allow the administrator to set a
minimum and maximum refresh and retry time either
per-zone, per-view, or globally.  These options are
valid for slave and stub zones, and clamp the SOA
refresh and retry times to the specified values.
The following defaults apply. min-refresh-time 300
seconds, max-refresh-time 2419200 seconds (4 weeks),
min-retry-time 500 seconds, and max-retry-time
1209600 seconds (2 weeks).""",
    }

g_nc_keywords['min-roots'] = \
    {
        'default': "2",
        'validity': {'range': {1, 1024}},
        'found-in': {'options', 'view'},
        'introduced': '8.3',  # 'min-roots' has not been introduced yet
        'obsoleted': '9.14',
        'topic': 'tuning, inert, not implemented',
        'comment': """The minimum number of root servers that is required
for a request for the root servers to be accepted.
The default is 2.""",
    }

g_nc_keywords['minimal-any'] = \
    {
        'default': 'false',  # was 'no' in v9.11
        'validity': {'regex': r"(true|false|yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.11',
        'topic': 'DNS',
        'comment': """If yes, then when generating responses the server will only add records to the authority
and additional data sections when they are required (e.g. delegations, negative responses).
This may improve the performance of the server. The default is no.
Note: Was renamed from 'minimal-response' in v9.11.0.""",
    }

g_nc_keywords['minimal-response'] = \
    {
        'default': 'no-auth-recursive',  # was 'no' in v9.11
        'validity': {'regex': r"(yes|no|no-auth|no-auth-recursive)"},
        'found-in': {'options', 'view'},
        'introduced': '9.2',
        'topic': 'DNS',
        'comment': '',
    }

g_nc_keywords['multiple-cnames'] = \
    {
        'default': "no",
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options'},
        'introduced': '8.1',  # inert since 9.2, still inert at 9.6.3
        'obsoleted': '9.14',
        'topic': 'inert',
        'comment': """This option was used in BIND 8 to allow a domain name to have multiple CNAME records
in violation of the DNS standards. BIND 9.2 onwards always strictly enforces the CNAME
rules both in master files and dynamic updates.""",
    }

g_nc_keywords['multi-master'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.3.0',
        'topic': 'DNS, master',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment': """This should be set when you have multiple masters for
a zone and the addresses refer to different machines.
If yes, named will not log when the serial number on
the master is less than what named currently has.
The default is no.""",
    }

g_nc_keywords['named-xfer'] = \
    {
        'default': None,
        'validity': {'function': 'path_name'},
        'found-in': {'options'},
        'introduced': '8.1',
        'obsoleted': '9.14',
        'topic': 'obsoleted, inert',
        'comment': """This option is obsolete. It was used in BIND 8 to
specify the pathname to the named-xfer program.
In BIND 9, no separate named-xfer program is needed;
its functionality is built into the name server.""",
    }

g_nc_keywords['new-zones-directory'] = \
    {
        'default': None,
        'validity': {'function': 'quoted_path_name'},
        'found-in': {'options', 'view'},
        'introduced': '9.12',
        'topic': 'zone',
        'comment': '',
    }

g_nc_keywords['no-case-compress'] = \
    {
        'default': {0: {'addr': 'none'}},
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view'},
        'introduced': '9.10',
        'topic': 'filtering, access control',
        'comment':
            """Specifies a list of addresses which require responses
to use case-insensitive compression.
This ACL can be used when named needs to work with
clients that do not comply with the requirement in
RFC 1034 to use case-insensitive name comparisons
when checking for matching domain names.

If left undefined, the ACL defaults to none:
case-insensitive compression will be used for all
clients.

If the ACL is defined and matches a client, then case
will be ignored when compressing domain names in DNS
responses sent to that client.

This can result in slightly smaller responses: if a
response contains the names "example.com" and
"example.COM", case-insensitive compression would treat
the second one as a duplicate. It also ensures that the
case of the query name exactly matches the case of the
owner names of returned records, rather than matching
the case of the records entered in the zone file. This
allows responses to exactly match the query, which is
required by some clients due to incorrect use of
case-sensitive comparisons.

Case-insensitive compression is always used in AXFR and
IXFR responses, regardless of whether the client
matches this ACL.

There are circumstances in which named will not
preserve the case of owner names of records: if a zone
file defines records of different types with the same
name, but the capitalization of the name is different
(e.g., "www.example.com/A" and"WWW.EXAMPLE.COM/AAAA"),
then all responses for that name will use the first
version of the name that was used in the zone file.
This limitation may be addressed in a future release.
However, domain names specified in the rdata of
resource records (i.e., records of type NS, MX, CNAME,
etc) will always have their case preserved unless the
client matches this ACL.""",
    }

g_nc_keywords['nocookie-udp-size'] = \
    {
        'default': 4096,
        'validity': {'range': {128, 4096}},  # max of 'max-udp-size'; bin/named/server.c
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'UDP',
        'comment': '',
    }

g_nc_keywords['nosit-udp-size'] = \
    {
        'default': None,  # this too is compile-time option
        'validity': {'range': {128, 32767}},
        'found-in': {'options', 'view'},
        'introduced': '9.10.0',
        'obsoleted': '9.11.0',  # Truly removed at 9.17.0
        'topic': 'UDP ',
        'comment': """Sets the maximum size of UDP responses that will be sent to queries without a valid
source identity token. A value below 128 will be silently raised to 128. The default value
is 4096, but the max-udp-size option may further limit the response size.""",
    }

g_nc_keywords['notify'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no|master\-only|explicit)'},
        # In 8.2 to 9.6.3?, yes/no   TODO: when did 'master-only' and 'explicit' got introduced to 'notify'?
        'found-in': {'options', 'view', 'zone'},
        # In 8.2, only found in ['zone']['type']['master']
        # In 8.2, only found in ['zone']['type']['slave']
        # In 8.2, only found in ['zone']['type']['stub']
        'introduced': '8.1',
        'topic': 'transfer',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'primary', 'secondary'},
        # not found in ['zone']['slave']
        # not found in ['zone']['stub']
        # not found in ['zone']['forward']
        # not found in ['zone']['hint']
        'comment': """If yes (the default), DNS NOTIFY messages are sent
when a zone the server is authoritative for changes,
see Section 4.1. The messages are sent to the servers
listed in the zone's NS records (except the master
server identified in the SOA MNAME field), and to any
servers listed in the also-notify option.
If master-only, notifies are only sent for master
zones. If explicit, notifies are sent only to servers
explicitly listed using also-notify. If no, no
notifies are sent.
The notify option may also be specified in the zone
statement, in which case it overrides the options
notify statement. It would only be necessary to turn
off this option if it caused slaves to crash.""",
    }

g_nc_keywords['notify-delay'] = \
    {
        'default': 5,
        'validity': {'range': {0, 1024}},
        'unit': 'second',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.5.0',
        'topic': 'tuning',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment': """The delay, in seconds, between sending sets of notify
messages for a zone. The default is five (5) seconds.
The overall rate that NOTIFY messages are sent for all
zones is controlled by serial-query-rate.""",
    }

g_nc_keywords['notify-rate'] = \
    {
        'default': '20',
        'validity': {'range': {0, 2100000000}},
        'found-in': {'options'},
        'unit': 'request_per_second',
        'introduced': '9.11.0',
        'topic': 'notify, tuning, transfer',
        'comment':
            """The rate at which NOTIFY request will be sent during
normal zone maintenance operation. (NOTIFY requests due
to initial zone loading are subject to a separate rate
limit; see startup-notify-rate.) The default is 20 per
second.  The lowest possible rate is one per secon;
when set to zero, it will silently be raised to one.""",
    }

g_nc_keywords['notify-source'] = \
    {
        'default': '*',  # was 'None' in v9.11
        'validity': {'function': 'ip4addr_port_dscp_list'},
        'found-in': {'options', 'view', 'zone', 'server'},
        'introduced': '9.1',
        'topic': 'notify, transfer, interface, data layer, DSCP, query address',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment':
            """notify-source determines which local source address,
and optionally UDP port, will be used to send NOTIFY
messages. This address must appear in the slave server's
masters zone clause or in an allow-notify clause.
This statement sets the notify-source for all zones, but
can be overridden on a per-zone or per-view basis by
including a notify-source statement within the zone or
view block in the configuration file.
NOTE
Solaris 2.5.1 and earlier does not support setting the
source address for TCP sockets.""",
    }

g_nc_keywords['notify-source-v6'] = \
    {
        'default': '*',  # was 'None' in v9.11
        'validity': {'function': 'ip6addr_port_dscp_list'},
        'found-in': {'options', 'view', 'zone', 'server'},
        'introduced': '9.1',
        'topic': 'transfer, interface, data layer, DSCP',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment':
            """Like notify-source, but applies to notify messages
sent to IPv6 addresses.  notify-source determines which
local source address, and optionally UDP port, will be
used to send NOTIFY messages. This address must appear in
the slave server's masters zone clause or in an
allow-notify clause. This statement sets the
notify-source for all zones, but can be overridden on a
per-zone or per-view basis by including a notify-source
statement within the zone or view block in the
configuration file.
NOTE
Solaris 2.5.1 and earlier does not support setting the
source address for TCP sockets.""",
    }

g_nc_keywords['notify-to-soa'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.5.0',
        'topic': 'notify, hidden-master',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """If yes do not check the nameservers in the
NS RRset against the SOA MNAME. Normally a NOTIFY
message is not sent to the SOA MNAME (SOA ORIGIN) as
it is supposed to contain the name of the ultimate
master. Sometimes, however, a slave is listed as the
SOA MNAME in hidden master configurations and in that
case you would want the ultimate master to still send
NOTIFY messages to all the nameservers listed in the
NS RRset.""",
    }

g_nc_keywords['nsec3-test-zone'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'view'},
        'introduced': '9.6.0',
        'topic': 'DNSSEC',
        'comment': '',
    }

g_nc_keywords['nsec3param'] = \
    {
        'default': None,
        'validity': {'function': 'dnssec_policy_nsec3param'},
        'found-in': {'dnssec-policy'},
        'introduced': '9.16.0',
        'topic': 'DNSSEC',
        'comment': """Use NSEC3 instead of NSEC, and optionally set the NSEC3 parameters.

Here is an example of an ``nsec3`` configuration:

    nsec3param iterations 0 optout no salt-length 0;

The default is to use NSEC.  The ``iterations``, ``optout`` and
``salt-length`` parts are optional, but if not set, the values in
the example above are the default NSEC3 parameters. Note that you don't
specify a specific salt string, :iscman:`named` will create a salt for you
of the provided salt length.""",
    }

g_nc_keywords['nta-lifetime'] = \
    {
        'default': 3600,
        'validity': {'range': {0, 65535}},
        'unit': 'duration',
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'negative trust, DNSSEC, NTA',
        'comment': '',
    }

g_nc_keywords['nta-recheck'] = \
    {
        'default': 300,
        'validity': {'range': {0, 65535}},
        'unit': 'duration',
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'negative trust, DNSSEC, NTA',
        'comment': '',
    }

g_nc_keywords['nxdomain-redirect'] = \
    {
        'default': None,
        'validity': {'string'},
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'nxdomain',
        'comment': '',
    }

g_nc_keywords['padding'] = \
    {
        'default': '0',
        'validity': {'range': {0, 512}},
        'unit': 'block_byte_size',
        'found-in': {'server'},
        'introduced': '9.12.0',
        'topic': 'UDP, data layer, server',
        'comment': '',
    }

g_nc_keywords['parent-ds-ttl'] = \
    {
        'default': "",
        'validity': {'range': {0, 3660}},
        'unit': 'ttl',
        'found-in': {'dnssec-policy'},  # removed from 'options' 9.12
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment': "",
    }

g_nc_keywords['parent-propagation-delay'] = \
    {
        'default': "",
        'validity': {'range': {0, 3660}},
        'unit': 'second',
        'found-in': {'dnssec-policy'},  # removed from 'options' 9.12
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment': "",
    }

g_nc_keywords['parent-registration-delay'] = \
    {
        'default': "",
        'validity': {'range': {0, 3660}},
        'unit': 'second',
        'found-in': {'dnssec-policy'},  # removed from 'options' 9.12
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment': "",
    }

g_nc_keywords['parental-source'] = \
    {
        'default': '*',
        'validity': {'function': 'ip4addr_port_dscp_list'},
        'found-in': {'options', 'view'},  # added 'options' in v9.19?
        'introduced': '9.18',
        'topic': 'DoH',
        'comment': '',
    }

g_nc_keywords['parental-source-v6'] = \
    {
        'default': '*',
        'validity': {'function': 'ip6addr_port_dscp_list'},
        'found-in': {'options', 'view'},  # added 'options' in v9.19?
        'introduced': '9.18',
        'topic': 'DoH',
        'comment': '',
    }

g_nc_keywords['pid-file'] = \
    {
        'default': '"/run/named/named.pid"',
        'validity': {'function': "path_name"},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system',
        'comment': """The pathname of the file the server writes its
process ID in. If not specified, the default is
/var/run/named/named.pid. The PID file is used by
programs that want to send signals to the running
name server. Specifying pid-file none disables the
use of a PID file - no file will be written and any
existing one will be removed.
Note that none is a keyword, not a filename, and
therefore is not enclosed in double quotes.""",
    }

g_nc_keywords['port'] = \
    {
        'default': 53,
        'validity': {'range': {1, 65535}},
        'found-in': {'options', 'primaries', 'masters', 'also-notify',
                     'alt-transfer-source', 'alt-transfer-source-v6',
                     'forwarders', 'statistics-channels', 'controls', 'parental-source',
                     'parental-source-v6', 'query-source', 'query-source-v6',
                     'parental-agents'},
        'introduced': '9.1',
        'topic': 'operating-system, interface, transport layer',
        'comment': """The UDP/TCP port number the server uses for receiving and sending DNS protocol traffic.

The default is 53.

This option is mainly intended for server testing; a server using a
port other than 53 will not be able to communicate with the global DNS.""",
    }

g_nc_keywords['prefer-server-ciphers'] = \
    {
        'default': 'no',
        'validity': {'boolean'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'TLS, HTTPS, DoH',
        'comment': '',
    }

g_nc_keywords['preferred-glue'] = \
    {
        'default': "A",
        'validity': {'regex': r"([A|AAAA|none)"},
        'found-in': {'options', 'view'},
        'introduced': '8.3',
        'topic': 'dual-stack',
        'comment': """If specified, the listed type (A or AAAA) will be emitted
before other glue in the additional section of a query
response.
The default is to prefer A records when responding to
queries that arrived via IPv4 and AAAA when responding
to queries that arrived via IPv6.""",
    }

g_nc_keywords['prefetch'] = \
    {
        'default': "2 9",
        'validity': {'regex': r"(([1-9])|10)\s+((7-9])|([0-9]{2-3})))"},
        'found-in': {'options', 'view'},
        'unit': 'second, second',
        'introduced': '9.10',
        'topic': 'tuning, cache, caching',
        'comment': """When a query is received for cached data which is to expire
shortly, named can refresh the data from the authoritative
server immediately, ensuring that the cache always has an
answer available.
The prefetch specifies the "trigger" TTL value at which
prefetch of the current query will take place: when a cache
record with a lower TTL value is encountered during query
processing, it will be refreshed.
Valid trigger TTL values are 1 to 10 seconds.
Values larger than 10 seconds will be silently reduced to 10.
Setting a trigger TTL to zero (0) causes prefetch to be disabled.
The default trigger TTL is 2.
An optional second argument specifies the "eligibility"
TTL: the smallest original TTL value that will be accepted
for a record to be eligible for prefetching. The eligibility
TTL must be at least six seconds longer than the trigger TTL;
if it isn't, named will silently adjust it upward.
The default eligibility TTL is 9.""",
    }

g_nc_keywords['protocols'] = \
    {
        'default': 'TLSv1.3',
        'validity': {'regex': r'(TLSv1.2|TLSv1.3)'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'TLS, HTTPS, DoH',
        'comment': '',
    }

g_nc_keywords['provide-ixfr'] = \
    {
        'default': 'true',  # was 'yes' in v9.11
        'validity': {'regex': "(true|false|yes|no)"},
        'found-in': {'options', 'view', 'server'},
        # moved from 'server' to 'options' on 9.2
        'introduced': '9.0.0',
        'topic': 'transfer, server',
        'comment': """The provide-ixfr clause determines whether the local
server, acting as master, will respond with an
incremental zone transfer when the given remote
server, a slave, requests it. If set to yes ,
incremental transfer will be provided whenever
possible. If set to no , all transfers to the remote
server will be nonincremental. If not set, the value
of the provide-ixfr option in the global options
block is used as a default.""",
    }

g_nc_keywords['pubkey'] = \
    {
        'default': None,
        'occurs-multiple-times': True,
        'validity': {'function': "pubkey"},
        'found-in': {'zone'},
        # In 8.2, only in ['zone']['type']['master']
        # In 8.2, only in ['zone']['type']['slave']
        # In 8.2, only in ['zone']['type']['stub']
        'introduced': '8.2',
        'obsoleted': '9.0',  # Still taking syntax in @ v9.15.0
        'topic': '',
        'zone-type': {'master', 'slave', 'stub'},
        'comment': """A pubkey represents a private key for this zone. It
is needed when this is the top level authoritative
zone served by this server and there is no chain of
trust to a trusted key. It is considered secure, so
that data that it signs will be considered secure.
The DNSSEC flags, protocol, and algorithm are
specified, as well as a base-64 encoded string
representing the key. """
    }

g_nc_keywords['publish-safety'] = \
    {
        'default': "",
        'validity': {'range': {0, 3660}},
        'found-in': {'dnssec-policy'},  # removed from 'options' in 9.12
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment': "",
    }

g_nc_keywords['purge-keys'] = \
    {
        'default': 'P90D',  # 90-day
        'validity': {'iso8601_time'},
        'unit': 'iso8601_time_duration',
        'found-in': {'options', 'dnssec-policy'},
        'introduced': '9.16.0',  # code appeared in 9.15.7
        'topic': 'DNSSEC',
        'comment': '',
    }
g_nc_keywords['qname-minimization'] = \
    {
        'default': 'relaxed',
        'validity': {'regex': "(strict|relaxed|disabled|off)"},
        'found-in': {'options', 'view'},
        'introduced': '9.14.0',
        'topic': 'QNAME',
        'comment': '',
    }

g_nc_keywords['queryport-pool-ports'] = \
    {
        'default': 0,
        'validity': {'integer'},
        'found-in': {'options', 'view'},
        'introduced': '9.4',
        'obsoleted': '9.10.5',
        'topic': 'query address, inert, obsoleted, ancient',
        'comment': '',
    }

g_nc_keywords['queryport-pool-updateinterval'] = \
    {
        'default': 0,
        'validity': {'integer'},
        'found-in': {'options', 'view'},
        'introduced': '9.4',
        'obsoleted': '9.10.5',
        'topic': 'query address, inert, obsolete, ancient',
        'comment': '',
    }

g_nc_keywords['query-source'] = \
    {
        'default': {'address': '*', 'port': '*'},
        'validity': {'function': "ip4addr_port_dscp_list"},
        'found-in': {'options', 'server', 'view'},
        'introduced': '8.1',
        'topic': 'query address',
        'comment':
            """If the server doesn't know the answer to a question,
it will query other nameservers. query-source specifies
the address and port used for such queries.
For queries sent over IPv6, there is a separate
query-source-v6 option. If address is * or is omitted,
a wildcard IP address ( INADDR_ANY ) will be used.
If port is * or is omitted, a random unprivileged
port will be used. The defaults are:

query-source address * port *;
query-source-v6 address * port *

Note: query-source currently applies only to UDP
queries; TCP queries always use a wildcard IP
address and a random unprivileged port."""
    }

g_nc_keywords['query-source-v6'] = \
    {
        'default': {'address': '*', 'port': '*'},
        'validity': {'function': "ip6addr_port_dscp_list"},
        'found-in': {'options', 'server', 'view'},
        'introduced': '9.4',  # 8.4?
        'topic': 'query address',
        'comment': '',
    }

g_nc_keywords['querylog'] = \
    {
        'default': None,
        'validity': {'regex': "(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'statistics, query',
        'comment': """Specify whether query logging should be started when named starts. If querylog is not
specified, then the query logging is determined by the presence of the logging category
queries.""",
    }

g_nc_keywords['random-device'] = \
    {
        'default': "\"/dev/random\"",
        'validity': {'function': "quoted_path_name",
                     'regex': '(none)'},
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'operating-system',
        'comment': """The source of entropy to be used by the server. Entropy is
primarily needed for DNSSEC operations, such as TKEY
transactions and dynamic update of signed zones. This
options specifies the device (or file) from which to
read entropy.

If this is a file, operations requiring entropy will
fail when the file has been exhausted. If not
specified, the default value is /dev/random (or
equivalent) when present, and none otherwise.

The randomdevice option takes effect during the
initial configuration load at server startup time
and is ignored on subsequent reloads.""",
    }

g_nc_keywords['rate-limit'] = \
    {
        'default': None,
        'validity': None,
        'found-in': {'options', 'view'},
        'introduced': '9.7.0',
        'topic': 'operating-system, response rate limiting',
        'comment': '',
    }

g_nc_keywords['recursing-file'] = \
    {
        'default': '"named.recursing"',
        'validity': {'function': "path_name"},
        'found-in': {'options'},
        'introduced': '9.5.0',
        'topic': 'operating-system',
        'comment': """The pathname of the file the server dumps the queries
that are currently recursing when instructed to do so
with rndc recursing.

If not specified, the default is named.recursing.""", }

g_nc_keywords['recursion'] = \
    {
        'default': 'true',  # was 'yes' in v9.11
        'validity': {'regex': r"(true|false|yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '8.1',
        'topic': 'recursion, cache, caching, query',
        'comment': """If yes, and a DNS query requests recursion, then the
server will attempt to do all the work required to
answer the query.

If recursion is off and the server does not already
know the answer, it will return a referral response.

The default is yes.

Note that setting recursion no does not prevent
clients from getting data from the server's cache;
it only prevents new data from being cached as
an effect of client queries.

Caching may still occur as an effect the server's
internal operation, such as NOTIFY address lookups.""",
    }

g_nc_keywords['recursive-clients'] = \
    {
        'default': '1000',
        'validity': {'range': {0, 32768}},
        'found-in': {'options'},
        'unit': 'connections',
        'introduced': '9.0.0',
        'topic': 'operating-system, server resource',
        'comment':
            """The maximum number ("hard quota") of simultaneous
            recursive lookups the server will perform on behalf of
            clients.
            
            The default is 1000.
            
            Because each recursing client uses a fair bit of
            memory (on the order of 20 kilobytes), the value of
            the recursive-clients option may have to be decreased
            on hosts with limited memory.
            
            recursive-clients defines a "hard quota" limit for
            pending recursive clients: when more clients than this
            are pending, new incoming requests will not be
            accepted, and for each incoming request a previous
            pending request will also be dropped.
            
            A "soft quota" is also set. When this lower quota is
            exceeded, incoming requests are accepted, but for each
            one, a pending request will be dropped.
            
            If recursive-clients is greater than 1000, the soft
            quota is set to recursive-clients minus 100; otherwise it
            is set to 90% of recursive-clients.""",
    }

g_nc_keywords['request-expire'] = \
    {
        'default': 'true',  # was 'yes' in v9.11
        'validity': {'regex': r'(true|false|yes|no)'},
        'found-in': {'options', 'view', 'server', 'zone'},
        'introduced': '9.11.0',
        'topic': 'transfer, server',
        'zone-type': {'slave', 'mirror', 'local', 'secondary'},
        'comment': '',
    }

g_nc_keywords['request-ixfr'] = \
    {
        'default': 'true',  # was 'yes' in v9.11
        'validity': {'regex': r'(true|false|yes|no)'},
        'found-in': {'options', 'view', 'server', 'zone'},
        'introduced': "9.1",
        'topic': 'transfer, server',
        'zone-type': {'slave', 'mirror', 'secondary'},
        'comment': """
Introduced to 'zone' section in v9.9.0.
Introduced to 'options' section in v9.12.0?
""",
    }

g_nc_keywords['request-nsid'] = \
    {
        'default': 'false',
        'validity': {'regex': r"(true|false|yes|no)"},
        'found-in': {'options', 'view', 'server'},
        'introduced': '9.5.0',
        'topic': 'NSID, server',
        'zone-type': {'local'},
        'comment': """If yes, then an empty EDNS(0) NSID (Name
Server Identifier) option is sent with all queries to
authoritative name servers during iterative resolution.
If the authoritative server returns an NSID option in
its response, then its contents are logged in the
resolver category at level info. The default is no.""",
    }

g_nc_keywords['require-server-cookie'] = \
    {
        'default': 'no',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'cookie',
        'comment':
            """If yes, require a valid server cookie before
            sending a full response to a UDP request from a
            cookie-aware client. BADCOOKIE is sent if there is a
            bad or nonexistent server cookie.
            
            The default is no.
            
            Users wishing to test that DNS COOKIE clients
            correctly handle BADCOOKIE, or who are getting a lot
            of forged DNS requests with DNS COOKIES present,
            should set this to yes. Setting this to yes results
            in a reduced amplification effect in a reflection
            attack, as the BADCOOKIE response is smaller than a
            full response, while also requiring a legitimate
            client to follow up with a second query with the
            new, valid, cookie.""",
    }

g_nc_keywords['request-sit'] = \
    {
        'default': None,  # also a compile-time option,
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view', 'server'},
        'introduced': '9.10.0',
        'obsoleted': '9.11.0',
        'topic': 'EDNS',
        'comment': """If yes, then a SIT (Source Identity Token) EDNS
option is sent along with the query.

If the resolver has previously talked to the server,
the SIT returned in the previous transaction is sent.

This is used by the server to determine whether the
resolver has talked to it before.  A resolver sending
the correct SIT is assumed not to be an off-path
attacker sending a spoofed-source query; the query is
therefore unlikely to be part of a
reflection/amplification attack, so resolvers sending
a correct SIT option are not subject to response rate
limiting (RRL). Resolvers which do not send a correct
SIT option may be limited to receiving smaller
responses via the nosit-udp-size option.""",
    }

g_nc_keywords['require-server-cookie'] = \
    {
        'default': 'no',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'server resource',
        'comment': '',
    }

g_nc_keywords['reserved-sockets'] = \
    {
        'default': '512',
        'validity': {'range': {128, 65535}},
        'unit': 'file descriptors',
        'found-in': {'options'},
        'introduced': '9.5.0',
        'topic': 'server resource',
        'comment':
            """The number of file descriptors reserved for TCP,
            stdio, etc.
            
            This needs to be big enough to cover the number of
            interfaces named listens on, tcp-clients as well as
            to provide room for outgoing TCP queries and incoming
            zone transfers.
            
            The default is 512.
            
            The minimum value is 128 and the maximum value is 128
            less than maxsockets (-S).
            
            This option may be removed in the future.
            
            This option has little effect on Windows.""",
    }

g_nc_keywords['resolver-nonbackoff-tries'] = \
    {
        'default': 3,
        'validity': {'range': (0, 30)},
        'found-in': {'options', 'view'},
        'introduced': '9.12',
        'topic': 'tuning',
        'comment': '',
    }

g_nc_keywords['resolver-query-timeout'] = \
    {
        'default': 800,  # was 10 in v9.15;  was 10000 in v9.11
        'validity': {'range': (0, 30000)},  # was 0..30 in v9.8.0
        'unit': 'millisecond',  # was 'second' in v9.8.0
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'topic': 'filtering, access control',
        'comment':
            """The amount of time in millisecond the resolver will
            spend attempting to resolve a recursive query before
            failing.
            
            Default is 10000.
            
            A value of 300 or less are in seconds unit.
            Setting it to 0 will result in the default being used.""",
    }

g_nc_keywords['resolver-retries-interval'] = \
    {
        'default': '800',
        'validity': 'integer',
        'unit': 'millisecond',
        'found-in': {'options', 'view'},
        'introduced': '9.12',
        'topic': 'tuning',
        'comment': """
""",
    }

g_nc_keywords['response-padding'] = \
    {
        'default': None,
        'validity': {'function': 'address_match_list',
                     'size': 'block_size'},
        'found-in': {'options', 'view'},
        'introduced': '9.12',
        'topic': '',
        'comment': """
""",
    }

g_nc_keywords['response-policy'] = \
    {
        'default': None,
        'validity': {'function': 'response_policy'},
        'found-in': {'options', 'view'},
        'introduced': '9.8.0',
        'topic': 'RPZ rewriting, response rate limiting',
        'comment': """
Option 'passthru' and 'disable' added in v9.9.0.
""",
    }

g_nc_keywords['retire-safety'] = \
    {
        'default': "",
        'validity': {'range': {0, 3660}},
        'found-in': {'dnssec-policy'},  # move from 'options' in 9.15
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment': "",
    }

g_nc_keywords['reuseport'] = \
    {
        'default': 'no',
        'validity': {'boolean'},
        'found-in': {'options'},
        'introduced': '9.18.0',
        'topic': 'resource, OS',
        'comment': '',
    }
g_nc_keywords['rfc2308-type1'] = \
    {
        'default': "no",
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '8.2',
        'obsoleted': '9.14',
        'topic': 'inert, not implemented',
        'comment': '',
    }

g_nc_keywords['root-delegation-only'] = \
    {
        'default': "",
        'validity': {'function': "tld_list"},
        'found-in': {'options', 'view'},
        'introduced': '9.3.0',
        'topic': 'TLD',
        'comment':
            """Turn on enforcement of delegation-only in TLDs (top
            level domains) and root zones with an optional
            exclude list.
            
            DS queries are expected to be made to and be answered
            by delegation only zones. Such queries and responses
            are treated as an exception to delegation-only
            processing and are not converted to NXDOMAIN
            responses provided a CNAME is not discovered at the
            query name.
            
            If a delegation only zone server also serves a child
            zone it is not always possible to determine whether
            an answer comes from the delegation only zone or the
            child zone. SOA NS and DNSKEY records are apex only
            records and a matching response that contains these
            records or DS is treated as coming from a child zone.
            RRSIG records are also examined to see if they are
            signed by a child zone or not. The authority section
            is also examined to see if there is evidence that the
            answer is from the child zone. Answers that are
            determined to be from a child zone are not converted
            to NXDOMAIN responses. Despite all these checks there
            is still a possibility of false negatives when a
            child zone is being served.  Similarly false
            positives can arise from empty nodes (no records at
            the name) in the delegation only zone when the query
            type is not ANY.
            
            Note some TLDs are not delegation only (e.g. "DE",
            "LV", "US" and "MUSEUM"). This list is not exhaustive.
            options {
                root-delegation-only exclude { "de"; "lv"; "us"; "museum"; };
            };
            """,
    }

g_nc_keywords['root-key-sentinel'] = \
    {
        'default': 'yes',
        'validity': {'regex': '(yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '9.13',
        'topic': '',
        'comment': '',
    }

g_nc_keywords['rrset-order'] = \
    {
        'default': {'class': 'any', 'type': "any", 'name': "*",
                    'order': 'random'},  # was 'order': 'cyclic' in v9.11
        'validity': {'function': 'rrset'},
        'found-in': {'options', 'view'},  # TBD moved 'zone' to 'view' in 9.17?
        'introduced': '8.2',
        'topic': 'RRSET, ordering, answer',
        'comment': '',
    }

g_nc_keywords['search'] = \
    {
        'default': '',  # incite
        'validity': {'string'},
        'occurs-multiple-times': False,
        'topblock': False,
        'found-in': {'dlz'},
        'introduced': "9.10.0",
    }
g_nc_keywords['secret'] = \
    {
        'default': '',  # incite
        'validity': {'string': 'base64'},
        'occurs-multiple-times': False,
        'topblock': False,
        'found-in': {'key'},
        'user-defined-indices': False,
        'multi-line-order-id': 999,  # after 'key {algorithm xx;'
        'introduced': "9.18.0",
    }

g_nc_keywords['secroots-file'] = \
    {
        'default': '"named.secroots"',
        'validity': {'function': "path_name"},
        'found-in': {'options'},
        'introduced': '9.8.0',
        'topic': 'operating-system, dnssec, rndc',
        'comment': """The pathname of the file the server dumps security roots to when
instructed to do so with rndc secroots.

If not specified, the default is named.secroots.""",
    }

g_nc_keywords['send-cookie'] = \
    {
        'default': 'true',  # was 'None' in v9.11
        'validity': {'regex': "(true|false|yes|no)"},
        'found-in': {'options', 'view', 'server'},  # 'options' added in 9.12?
        'introduced': '9.11.0',
        'topic': 'transfer, DSCP, server',
        'comment': '',
    }

g_nc_keywords['serial-queries'] = \
    {
        'default': 34,
        'validity': {'range': (1, 2222111222)},
        'found-in': {'options'},
        'introduced': '8.3',
        'obsoleted': '9.14',
        'topic': 'inert, obsoleted, ignored, zone transfer',
        'comment':
            """In BIND 8, the serial-queries option set the
            maximum number of concurrent serial number queries
            allowed to be outstanding at any given time.
            
            BIND 9 does not limit the number of outstanding
            serial queries and ignores the serial-queries option.
            Instead, it limits the rate at which the queries are
            sent as defined using the serial-query-rate option.""",
    }

g_nc_keywords['serial-query-rate'] = \
    {
        'default': "20",
        'validity': {'function': "time_duration"},
        'unit': 'query_per_second',
        'found-in': {'options'},
        'introduced': '9.2',
        'topic': 'transfer',
        'comment':
            """Slave servers will periodically query master servers to
find out if zone serial numbers have changed. Each such
query uses a minute amount of the slave server's
network bandwidth.
To limit the amount of bandwidth used, BIND 9 limits the
rate at which queries are sent.
The value of the serial-query-rate option, an integer, is
the maximum number of queries sent per second.
The default is 20 per second.
The lowest possible rate is one per second; when set to
zero, it will be silently raised to one.
In addition to controlling the rate SOA refresh queries
are issued at, serial-query-rate also controls the rate
at which NOTIFY messages are sent from both master and
slave zones.""",
    }

g_nc_keywords['serial-update-method'] = \
    {
        'default': 'date',  # changed from 'increment' in v9.12
        'validity': {'regex': r'(date|increment|unixtime)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.9.0',
        'topic': 'dynamic dns, ddns, SOA',
        'zone-type': {'master', 'primary'},
        'comment':
            """Zones configured for dynamic DNS may use this
option to set the update method that will be used for
the zone serial number in the SOA record.

With the default setting of serial-update-method
increment;, the SOA serial number will be incremented
by one each time the zone is updated.

When set to serial-update-method unixtime;, the SOA
serial number will be set to the number of seconds
since the UNIX epoch, unless the serial number is
already greater than or equal to that value, in
which case it is simply incremented by one.

`serial-update-method` is used for dynamic zones to
determne how the SOA SERIAL should be updated.  There
will likely be a separate configuration option for
the serial update method when resigning a zone.
""",
    }

g_nc_keywords['server-addresses'] = \
    {
        'default': None,
        'validity': {
            'function': 'bracket_ip_list',
        },
        'found-in': {'zone'},
        'introduced': '9.8.0',
        'topic': 'static-stub zone',
        'zone-type': {'static-stub'},
        'comment': 'Only meaningful for static-stub zone.',
    }

g_nc_keywords['server-id'] = \
    {
        'default': 'none',
        'validity': {
            'function': 'quoted_hostname',
            'regex': r"(none|hostname|[A-Za-z\-_]{1-64}(\.[A-Za-z0-9\-_]{1-64})*"
        },
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'NSID, server info',
        'comment': """The ID the server should report when receiving a Name
Server Identifier (NSID) query, or a query of the
name ID.SERVER with type TXT, class CHAOS. The primary purpose
of such queries is to identify which of a group of anycast
servers is actually answering your queries. Specifying
server-id none; disables processing of the queries.
Specifying server-id hostname; will cause named to use the
hostname as found by the gethostname() function.

The default server-id is none.

Note: Option 'hostname' was added in v9.8.0.""",
    }

g_nc_keywords['server-names'] = \
    {
        'default': None,
        'validity': {'function': 'fqdn_list'},
        'found-in': {'zone'},
        'introduced': '9.8.0',
        'topic': 'static stub zone',
        'zone-type': {'static-stub'},
        'comment': '',
    }
g_nc_keywords['servfail-ttl'] = \
    {
        'default': 1,
        'validity': {'range': {0, 30}},
        'unit': 'second',
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'tuning',
        'comment': '',
    }

g_nc_keywords['session-keyalg'] = \
    {
        'default': "hmac-sha256",
        'validity': {'regex': r"hmac\-(sha1|sha224|sha256|sha384|sha512|md5)"},
        'found-in': {'options'},
        'introduced': '9.7.0',
        'topic': 'session, ddns, nsupdate, rndc, TSIG',
        'comment': """The algorithm to use for the TSIG session key.

Valid values are hmac-sha1, hmac-sha224, hmac-sha256,
hmac-sha384, hmac-sha512 and hmac-md5.

If not specified, the default is hmac-sha256.

Used with 'nsupdate -l' and dhcpd.
""",
    }

g_nc_keywords['session-keyfile'] = \
    {
        'default': '"/run/named/session.key"',
        'validity': {'function': "path_name_qstring_or_none"},
        'found-in': {'options'},
        'introduced': '9.7.0',
        'topic': 'ddns, nsupdate, rndc, TSIG',
        'comment': """The pathname of the file into which to write a TSIG
session key generated by named for use by nsupdate -l.

If not specified, the default is /var/run/named/session.key.

(See Section 6.2, and in particular the discussion of
the update-policy statement's local option for more
information about this feature.)""",
    }

g_nc_keywords['session-keyname'] = \
    {
        'default': 'localddns',
        'validity': {'regex': r"[A-Za-z0-9]+"},
        'found-in': {'options'},  # TBD 'view'/'zone' removed by 9.17?
        'introduced': '9.7.0',
        'topic': 'session, ddns, nsupdate, rndc, TSIG',
        'comment': """The key name to use for the TSIG session key.

If not specified, the default is "local-ddns".

Used with 'nsupdate -l' and dhcpd.
""",
    }

g_nc_keywords['session-tickets'] = \
    {
        'default': 'no',
        'validity': {'boolean'},
        'found-in': {'tls'},
        'introduced': '9.18.0',
        'topic': 'TLS, HTTPS, DoH',
        'comment': '',
    }

g_nc_keywords['sig-signing-nodes'] = \
    {
        'default': 100,
        'validity': {'range': {1, 1024}},
        'unit': 'nodes_per_quantum',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.5.0',
        'topic': 'DNSSEC',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """Specify the maximum number of nodes to be examined in
each quantum when signing a zone with a new DNSKEY.

sig-signing-nodes specifies the number of nodes to be
examined in a quantum when signing a zone with a new
DNSKEY.  This presumable is to avoid keeping the
database connection open for a long time.  With the
current database approach this probably needs to stay.

The default is 100.""",
    }

g_nc_keywords['sig-signing-signatures'] = \
    {
        'default': 10,
        'validity': {'range': {1, 2 ** 32}},
        'unit': 'signing_per_quantum',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.6.0',
        'topic': 'dnssec, tuning',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """Specify at threshold number of signatures that will
terminate processing a quantum when signing a zone with a new DNSKEY.

`sig-signing-signatures` specifies a threshold number
of how many signatures will be generated in a quantum.
Similar to `sig-signing-nodes`.

The default is 10.""",
    }

g_nc_keywords['sig-signing-type'] = \
    {
        'default': 65534,
        'validity': {'range': {1, 65535}},
        'unit': 'RDATA_type',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.5.0',
        'topic': 'dnssec, tuning',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """Specify a private RDATA type to be used when generating
signing state records.

The default is 65534.

It is expected that this parameter may be removed in a
future version once there is a standard type.

`sig-signing-type` is internal record type number,
used to track zone signing process.  This likely will
go away in favor of a new method.

Signing state records are used to internally by named
to track the current state of a zone-signing process,
i.e., whether it is still active or has been completed.
The records can be inspected using the command:

    rndc signing-list zone.

Once named has finished signing a zone with a
particular key, the signing state record associated
with that key can be removed from the zone by running:

    rndc signing-clear keyid/algorithm zone.

To clear all of the completed signing state records
for a zone, use:

    rndc signing-clear all zone""",
    }

g_nc_keywords['sig-validity-interval'] = \
    {
        'default': 30,
        'validity': {'range': {0, 3660},
                     'regex': r"[0-9]{1-4}(\s+[0-9]{0-8)"},
        'unit': 'day',
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.0.0',
        'topic': 'dnssec, tuning',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """Specifies the number of days into the future when
DNSSEC signatures automatically generated as a result
of dynamic updates (Section 4.2) will expire.

There is an optional second field which specifies how
long before expiry that the signatures will be
regenerated. If not specified, the signatures will be
regenerated at 1/4 of base interval.

The second field is specified in days if the base
interval is greater than 7 days otherwise it is
specified in hours.

The default base interval is 30 days giving a
re-signing interval of 7 1/2 days.

The maximum values are 10 years (3660 days).

The signature inception time is unconditionally set to
one hour before the current time to allow for a limited
amount of clock skew.

`sig-validity-interval` specifies the number of days
a signature is valid.  The second optional value is
the refresh interval. Thos option will be replaced by
KASP configuration values "signatures-validity" and
"signatures-refresh".

The sig-validity-interval should be, at least, several
multiples of the SOA expire interval to allow for
reasonable interaction between the various timer and
expiry dates.""",
    }

g_nc_keywords['signatures-refresh'] = \
    {
        'default': "P5D",  # 5 days
        'unit': 'iso8601_time_duration',
        'validity': {'range': {0, 3660},
                     'function': 'iso8601_time_duration'},
        'found-in': {'dnssec-policy'},  # moved from 'options' in 9.16?
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment':
            """This determines how frequently an RRSIG record needs
            to be refreshed.
            
            The signature is renewed when the time until the
            expiration time is less than the specified interval.
            
            The default is P5D (5 days), meaning signatures that
            expire in 5 days or sooner are refreshed.""",
    }

g_nc_keywords['signatures-validity'] = \
    {
        'default': 'P2W',
        'validity': {'range': {0, 3660},
                     'function': 'iso8601_time_duration'},
        'found-in': {'dnssec-policy'},  # move from 'options' 9.16?
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment':
            """This indicates the validity period of an RRSIG record
            (subject to inception offset and jitter).
            
            The default is P2W (2 weeks).
            """,
    }

g_nc_keywords['signatures-validity-dnskey'] = \
    {
        'default': 'P2W',
        'validity': {'range': {0, 3660},
                     'function': 'iso8601_time_duration'},
        'found-in': {'dnssec-policy'},
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment':
            """This is similar to signatures-validity, but for DNSKEY
            records.
            
            The default is P2W (2 weeks).""",
    }

g_nc_keywords['sit-secret'] = \
    {
        'default': "",
        'validity': {'regex': r"[0-9a-fA-F]{8,10,16}"},
        'found-in': {'options'},
        'introduced': '9.10.0',
        'obsoleted': '9.11.0',
        'topic': 'EDNS',
        'comment': """If set, this is a shared secret used for generating
and verifying Source Identity Token EDNS options within
a anycast cluster. If not set the system will generate
a random secret at startup.

The shared secret is encoded as a hex string and needs
to be 128 bits for AES128, 160 bits for SHA1 and 256
bits for SHA256.""",
    }

g_nc_keywords['sortlist'] = \
    {
        'default': None,
        'validity': {'function': "address_match_nosemicolon"},
        'found-in': {'options', 'view'},
        'introduced': '8.2',
        'topic': 'answer, response',
        'comment': '',
    }

g_nc_keywords['stacksize'] = \
    {
        'default': 'default',  # changed to 'default' in v9.12
        'validity': {'function': "size_spec",
                     'regex': '(default|unlimited)'},
        'unit': 'byte',
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system',
        'comment': """The maximum amount of stack memory the server may use.
The default is default.""",
    }

g_nc_keywords['stale-answer-client-timeout'] = \
    {
        'default': 'off',
        'validity': {'regex': '(disabled|off)',
                     'range': {0, 32767}},
        'found-in': {'options', 'view'},  # added to 'options' in v9.19?
        'introduced': '9.18',
        'topic': '',
        'comment': '',
    }

g_nc_keywords['stale-answer-enable'] = \
    {
        'default': 'false',  # was 'yes' in v9.12
        'validity': {'regex': '(true|false|yes|no)'},
        'found-in': {'options', 'view'},  # 'options' added 9.13?
        'introduced': '9.12',
        'topic': 'answer, response',
        'comment': '',
    }

g_nc_keywords['stale-answer-ttl'] = \
    {
        'default': 30,
        'validity': {'function': 'ttlval'},
        'unit': 'delta_second',  # was 'second' in v9.12
        'found-in': {'options', 'view'},  # 'options' added 9.13?
        'introduced': '9.12',
        'topic': 'answer, response',
        'comment': '',
    }

g_nc_keywords['stale-cache-enable'] = \
    {
        'default': 'false',
        'validity': {'regex': '(true|false|yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '9.16',
        'topic': 'caching, cache',
        'comment': '',
    }

g_nc_keywords['stale-refresh-time'] = \
    {
        'default': 30,
        'validity': {'function': 'ttlval'},
        'unit': 'delta_second',
        'found-in': {'options', 'view'},
        'introduced': '9.18',
        'topic': '',
        'comment': """The default ``stale-refresh-time`` is 30 seconds, as :rfc:`8767` recommends""",
    }

g_nc_keywords['startup-notify-rate'] = \
    {
        'default': 20,
        'validity': {'range': {0, 2100000000}},
        'unit': 'request_per_second',
        'found-in': {'options'},
        'introduced': '9.11.0',
        'topic': 'tuning, transfer',
        'comment':
            """The rate at which NOTIFY requests will be sent when the
            name server is first starting up, or when zones have been
            newly added to the nameserver.  The default is 20 per
            second. The lowest possible rate is one per second; when
            set to zero, it will be silently raised to one.""",
    }

g_nc_keywords['statistics-file'] = \
    {
        'default': '"named.stats"',
        'validity': {'function': "path_name"},
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'operating-system, inert',  # inert at 9.0.0
        'comment': """The pathname of the file the server appends statistics
to when instructed to do so using rndc stats.

If not specified, the default is named.stats in the
server's current directory.""",
    }

g_nc_keywords['statistics-interval'] = \
    {
        'default': "60",
        'validity': 'integer',
        'found-in': {'options'},
        'introduced': '8.2',
        'obsoleted': '9.14.0',
        'topic': 'operating-system, server resource, periodic interval, inert, not implemented',
        'comment': """Name server statistics will be logged every
statistics-interval minutes.

The default is 60 minutes.

The maximum value is 28 days (40320 minutes).

If set to 0, no statistics will be logged.

Not yet implemented in Bind 9""",
    }

g_nc_keywords['streams-per-connection'] = \
    {
        'default': 100,
        'validity': {'range': {1, 65535}},
        'found-in': {'http'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': '',
    }

g_nc_keywords['support-ixfr'] = \
    {
        'default': "no",
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'server'},
        # In 8.2, not in ['options'], nor ['view']
        'introduced': '8.2',
        'obsoleted': '9.11',
        'topic': 'transfer, IXFR',
        'comment': '',
    }

g_nc_keywords['suppress-initial-notify'] = \
    {
        'default': 'no',
        'validity': {'boolean'},
        'found-in': {'options', 'view'},
        'introduced': '8.3',
        'obsoleted': '8.18',  # TBD when was it gone?
        'topic': 'notify',
        'comment': '',
    }

g_nc_keywords['synth-from-dnssec'] = \
    {
        'default': 'yes',
        'validity': {'regex': '(yes|no)'},
        'found-in': {'options', 'view'},  # when did 'options' get added?
        'introduced': '9.12',
        'topic': 'DNSSEC, cache, caching',
        'comment':
            """This option enables support for RFC 8198, Aggressive
Use of DNSSEC-Validated Cache.

It allows the resolver to send a smaller number of
queries when resolving queries for DNSSEC-signed
domains by synthesizing answers from cached NSEC and
other RRsets that have been proved to be correct
using DNSSEC.

The default is yes.

Note: DNSSEC validation must be enabled for this
option to be effective. This initial
implementation only covers synthesis of answers
from NSEC records; synthesis from NSEC3 is
planned for the future.
This will also be controlled by synth-from-dnssec.""",
    }

g_nc_keywords['tcp-advertised-timeout'] = \
    {
        'default': 300,
        'validity': {'range': {0, 65535}},
        'unit': 'millisecond',
        'found-in': {'options'},
        'introduced': '9.12',
        'topic': 'server resource',
        'comment':
            """The amount of time (in millisecond) the server will
            send in respones containing the EDNS TCP keepalive
            option.
            
            This informs a client of the amount of time it may
            keep the session open.
            
            The default is 300 (30 seconds), the minimum is 0, and
            the maximum is 65535 (about 1.8 hours).
            
            Values above the maximum or below the minimum will be
            adjusted with a logged warning.
            
            Note: This value must be greater than expected round
                  trip delay time; otherwise no client will ever
                  have enough time to submit a message.)
            
            This value can be updated at runtime by using
            
                'rndc tcp-timeouts'""",
    }

g_nc_keywords['tcp-clients'] = \
    {
        'default': 150,  # was 100
        'validity': {'range': {1, 2 ** 32 - 1}},
        'unit': 'TCP_connections',
        'found-in': {'options'},
        'introduced': '9.0.0',
        'topic': 'network layer, server resource',
        'comment':
            """The maximum number of simultaneous client TCP
connections that the server will accept.
            
The default is 150.""",
    }

g_nc_keywords['tcp-idle-timeout'] = \
    {
        'default': 300,
        'validity': {'range': {1, 1200}},
        'unit': 'centisecond',
        'found-in': {'options'},
        'introduced': '9.12',
        'topic': 'server resource',
        'comment':
            """The amount of time (in centisecond) the server waits
            on an idle TCP connection before closing it when the
            client is not using the EDNS TCP keepalive option.
            
            The default is 300 (30 seconds), the maximum is 1200
            (two minutes), and the minimum is 1 (one tenth of
            a second).
            
            Values above the maximum or below the minimum will be
            adjusted with a logged warning.
            
            Note: This value must be greater than expected round
                  trip delay time; otherwise no client will ever
                  have enough time to submit a message.)
            
            This value can be updated at runtime by using
            
               'rndc tcp-timeouts'""",
    }

g_nc_keywords['tcp-initial-timeout'] = \
    {
        'default': 300,
        'validity': {'range': {25, 1200}},
        'unit': 'centisecond',
        'found-in': {'options'},
        'introduced': '9.12',
        'topic': 'server resource',
        'comment':
            """The amount of time (in centisecond) the server waits
            on a new TCP connection for the first message from the
            client.
            
            The default is 300 (30 seconds), the minimum is
            25 (2.5 seconds), and the maximum is
            1200 (two minutes).
            
            Values above the maximum or below the minimum will be
            adjusted with a logged warning.
            
            Note: This value must be greater than expected round
                  trip delay time; otherwise no client will ever
                  have enough time to submit a message.)
            
            This value can be updated at runtime by using
            
                'rndc tcp-timeouts'""",
    }

g_nc_keywords['tcp-keepalive'] = \
    {
        'default': 'no',
        'validity': {'regex': '(yes|no)'},
        'found-in': {'server'},
        'introduced': '9.12',
        'topic': 'transport layer, TCP, server',
        'comment': '',
    }

g_nc_keywords['tcp-keepalive-timeout'] = \
    {
        'default': 300,
        'validity': {'range': {1, 65535}},
        'unit': 'centisecond',
        'found-in': {'options'},
        'introduced': '9.12',
        'topic': 'server resource',
        'comment':
            """The amount of time (in centisecond) the server waits
            on an idle TCP connection before closing it when the
            client is using the EDNS TCP keepalive option.
            
            The default is 300 (30 seconds), the maximum is 65535
            (1.8 hours), and the minimum is 1 (one tenth of
            a second).
            
            Values above the maximum or below the minimum will be
            adjusted with a logged warning.  (Note: This value must
            be greater than expected round trip delay time;
            otherwise no client will ever have enough time to submit
            a message.)  This value can be updated at runtime by
            using rndc tcp-timeouts.""",
    }

g_nc_keywords['tcp-listen-queue'] = \
    {
        'default': 10,
        'validity': {'range': {10, 2 ** 32 - 1}},
        'unit': 'listen_queue_depth',
        'found-in': {'options'},
        'introduced': '9.3.0',
        'topic': 'network layer, server resource',
        'comment':
            """The listen queue depth.

The default and minimum is 10.

If the kernel supports the accept filter "dataready"
this also controls how many TCP connections that will
be queued in kernel space waiting for some data before
being passed to accept.

Nonzero values less than 10 will be silently raised.

A value of 0 may also be used; on most platforms this
sets the listen queue length to a system-defined
default value.""",
    }

g_nc_keywords['tcp-only'] = \
    {
        'default': 'no',
        'validity': {'regex': '(yes|no)'},
        'found-in': {'server'},
        'introduced': '9.11.0',
        'topic': 'network layer, protocol, server',
        'comment': '',
    }

g_nc_keywords['tcp-receive-buffer'] = \
    {
        'default': 0,
        'validity': {'range': {0, 65535},
                     'string': 'unlimited'},
        'found-in': {'options'},
        'introduced': '9.18.0',
        'topic': 'TCP, buffer, resource',
        'comment': '',
    }

g_nc_keywords['tcp-send-buffer'] = \
    {
        'default': 0,
        'validity': {'range': {0, 2 ** 32 - 1},
                     'string': 'unlimited'},
        'found-in': {'options'},
        'introduced': '9.18.0',
        'topic': 'TCP, buffer, resource',
        'comment': '',
    }

g_nc_keywords['tkey-dhkey'] = \
    {
        'default': None,
        'validity': {'regex': r"\w\s+\w",
                     'function': 'key_name_tag'},
        'found-in': {'options'},
        'occurs-multiple-times': False,  # was True in 9.15? TBD
        'introduced': '9.0.0',
        'topic': 'operating-system, authentication, GSS, KRB5',
        'comment':
            """The Diffie-Hellman key used by the server to generate
            shared keys with clients using the Diffie-Hellman mode
            of TKEY.
            
            The server must be able to load the public and
            private keys from files in the working directory.
            
            In most cases, the keyname_base should be the server's
            host name.""",
    }

g_nc_keywords['tkey-domain'] = \
    {
        'default': None,
        'validity': {'regex': r"\w(\.\w)+",
                     'function': 'domainname'},
        'found-in': {'options'},
        'introduced': '9.0.0',
        'topic': 'operating-system, authentication, GSS, KRB5',
        'comment': """The domain appended to the names of all shared keys
generated with TKEY. When a client requests a TKEY
exchange, it may or may not specify the desired name
for the key.

If present, the name of the shared key will be client
specified part + tkey-domain.

Otherwise, the name of the shared key will be random
hex digits + tkey-domain.

In most cases, the domainname should be the server's
domain name, or an otherwise nonexistent subdomain
like "_tkey.domainname".

If you are using GSS-TSIG, this variable must be
defined, unless you specify a specific keytab
using tkey-gssapi-keytab.""",
    }

g_nc_keywords['tkey-gssapi-credential'] = \
    {
        'default': None,
        'validity': {'regex': r"\w/\w",
                     'function': 'quoted_string',
                     },
        'found-in': {'options'},
        'introduced': '9.4.0',
        'topic': 'operating-system, authentication, GSS, KRB5',
        'comment': """The security credential with which the server should
authenticate keys requested by the GSS-TSIG protocol.

Currently only Kerberos 5 authentication is available
and the credential is a Kerberos principal which the
server can acquire through the default system key file,
normally /etc/krb5.keytab.

The location keytab file can be overridden using the
tkey-gssapi-keytab option. Normally this principal is
of the form "DNS/server.domain".

To use GSS-TSIG, tkey-domain must also be set if a
specific keytab is not set with tkey-gssapi-keytab.""",
    }

g_nc_keywords['tkey-gssapi-keytab'] = \
    {
        'default': "\"/etc/krb5.keytab\"",
        'validity': {'function': "path_name"},
        'found-in': {'options'},
        'introduced': '9.8.0',
        'topic': 'operating-system, authentication, GSS, KRB5',
        'comment': """The KRB5 keytab file to use for GSS-TSIG updates.

If this option is set and tkey-gssapicredential is not
set, then updates will be allowed with any key matching
a principal in the specified keytab.

Currently only Kerberos 5 authentication is available
and the credential is a Kerberos principal which the
server can acquire through the default system key
file, normally /etc/krb5.keytab.""",
    }

g_nc_keywords['tls-port'] = \
    {
        'default': 853,
        'validity': {'range': {1, 65535}},
        'found-in': {'options'},
        'introduced': '9.18',
        'topic': 'DNS-over-HTTP, DoH',
        'comment': """An IP port number. The number is limited to 1 
through 65535, with values below 1024 typically 
restricted to use by processes running as root. 
In some cases, an asterisk (*) character can be used 
as a placeholder to select a random high-numbered port.""",
    }

g_nc_keywords['topology'] = \
    {
        'default': 'none',
        'validity': {'function': 'address_match_list'},
        'found-in': {'options', 'view'},
        'introduced': '9.13',
        'obsoleted': '9.18.0',
        'topic': 'topology',
        'comment': '',
    }

g_nc_keywords['transfer-format'] = \
    {
        'default': 'many-answers',  # was 'one-answer' in 8.1
        'validity': {'regex': r'(one\-answer|many\-answer)'},
        'found-in': {'options', 'view', 'server'},
        'introduced': '8.1',
        'topic': 'transfer, server',
        'comment':
            """Zone transfers can be sent using two different formats,
            one-answer and many-answers.
            
            The transfer-format option is used on the master server
            to determine which format it sends. one-answer uses one
            DNS message per resource record transferred.
            
            many-answers packs as many resource records as possible
            into a message. many-answers is more efficient, but is
            only supported by relatively new slave servers, such as
            BIND 9, BIND 8.x and BIND 4.9.5 onwards.
            
            The many-answers format is also supported by recent
            Microsoft Windows nameservers.
            
            The default is many-answers.
            
            transfer-format may be overridden on a per-server basis
            by using the server statement.""",
    }

g_nc_keywords['transfer-message-size'] = \
    {
        'default': 20480,
        'validity': {'range': {512, 65535}},
        'unit': 'uncompressed_byte',
        'found-in': {'options'},
        'introduced': '9.11',  # Also used in 8.1
        'topic': 'transfer',
        'comment':
            """This is the upper bound on the uncompressed size of DNS
            messages used in zone transfers over TCP.  If the message
            grows larger than this size, additional messages will be
            used to complete the zone transfer.  (Note, however, that
            this is a hint, not a hard limit, if a message contain a
            single resource record whose RDATA does not fit within
            the size limit, a larger message will be permitted so the
            record can be transferred.)""",
    }

g_nc_keywords['transfer-per-ns'] = \
    {
        'default': '2',
        'validity': {'range': {1, 65535}},
        'unit': 'concurrent_inbound_zone_transfers',
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'zone transfer',
        'comment':
            """The maximum number of inbound zone transfers that can
            be running concurrently.  The default value is 10.
            Increasing transfer-in may speed up the convergence of
            slave zones, but it also increases the load of a local
            system.""",
    }

g_nc_keywords['transfer-source'] = \
    {
        'default': '*',  # was 'None' in v9.11
        'validity': {'function': 'ip4addr_port_dscp'},
        'unit': 'ip_address',
        'found-in': {'options', 'view', 'zone', 'server'},
        # was in 9.3 'server', now???
        'introduced': '8.2',
        'topic': 'transfer, data layer, interface, DSCP, query address',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment':
            """transfer-source determines which local address will be
            bound to IPv4 TCP connections used to fetch zones
            transferred inbound by the server. It also determines
            the source IPv4 address, and optionally the UDP port,
            used for the refresh queries and forwarded dynamic
            updates.
            
            If not set, it defaults to a system controlled value
            which will usually be the address of the interface
            "closest to" the remote end. This address must appear
            in the remote end's allow-transfer option for the
            zone being transferred, if one is specified.
            
            This statement sets the transfer-source for all zones,
            but can be overridden on a per-view or per-zone basis
            by including a transfer-source statement within the
            view or zone block in the configuration file.
            NOTE: Solaris 2.5.1 and earlier does not support
            setting the source address for TCP sockets.""",
    }

g_nc_keywords['transfer-source-v6'] = \
    {
        'default': '*',  # was 'None' in v9.11
        'validity': {'function': 'ip6addr_port_dscp_list'},
        'found-in': {'options', 'view', 'zone', 'server'},
        'introduced': '9.0.0',
        'topic': 'transfer, DSCP, server',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment': """The same as transfer-source, except zone transfers are
performed using IPv6. transfer-source determines which
local address will be bound to IPv4 TCP connections
used to fetch zones transferred inbound by the server.
It also determines the source IPv4 address, and
optionally the UDP port, used for the refresh queries
and forwarded dynamic updates.

If not set, it defaults to a system controlled value
which will usually be the address of the interface
"closest to" the remote end. This address must
appear in the remote end's allow-transfer option for
the zone being transferred, if one is specified.
This statement sets the transfer-source for all
zones, but can be overridden on a per-view or
per-zone basis by including a transfer-source
statement within the view or zone block in the
configuration file.

NOTE: Solaris 2.5.1 and earlier does not support
setting the source address for TCP sockets.""",
    }

g_nc_keywords['transfers'] = \
    {
        'default': None,
        'validity': {'range': {1, 4096, }, },
        'unit': 'concurrent_inbound_zone_transfers',
        'found-in': {'server'},  # not in 'options/view' clause
        'introduced': '8.2',
        # In 9.0, ['options']['transfers'] supported???
        # In 9.0, ['view']['transfers'] supported???
        'topic': 'zone transfer, server',
        'comment': """Zone transfers can be sent using two different formats, """
    }

g_nc_keywords['transfers-in'] = \
    {
        'default': 10,
        'validity': {'range': {0, 1024}},
        'found-in': {'options'},
        'unit': 'concurrent_inbound_transfers',
        'introduced': '8.1',
        'topic': 'transfer',
        'comment':
            """The maximum number of inbound zone transfers that can
            be running concurrently.  The default value is 10.
            Increasing transfer-in may speed up the convergence of
            slave zones, but it also increases the load of a local
            system.""",
    }

g_nc_keywords['transfers-out'] = \
    {
        'default': 10,
        'validity': {'function': "time_duration"},  # faux-checked in 8.1
        'unit': 'concurrent_outbound_transfers',
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'transfer',
        'comment': """The maximum number of outbound zone transfers that
can be running concurrently.

Zone transfer requests in excess of the limit will be
refused.

The default value is 10.""",
    }

g_nc_keywords['transfers-per-ns'] = \
    {
        'default': 2,
        'validity': {'function': "time_duration"},
        'validity': {'range': {1, 65535}},
        'unit': 'concurrent_inbound_zone_transfers',
        'found-in': {'options'},
        'introduced': '8.1',
        'topic': 'transfer',
        'comment':
            """The maximum number of inbound zone transfers that can
be concurrently transferring from a given remote name
server.

The default value is 2.

Increasing transfers-per-ns may speed up the
convergence of slave zones, but it also may increase
the load on the remote name server. transfers-per-ns
may be overridden on a per-server basis by using the
transfers phrase of the server statement.""",
    }

g_nc_keywords['treat-cr-as-space'] = \
    {
        'default': "yes",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '8.3',
        'obsoleted': '9.14.0',  # still inert at 9.6.3
        'topic': 'operating-system, inert',
        'comment': """This option was used in BIND 8 to make the server
treat carriage return (\"\\r\") characters the same way
as a space or tab character, to facilitate loading of
zone files on a UNIX system that were generated on an
NT or DOS machine. In BIND 9, both UNIX \"\\n\" and
NT/DOS \"\\r\\n\" newlines are always accepted, and the
option is ignored.""",
    }

g_nc_keywords['trust-anchor-telemetry'] = \
    {
        'default': 'yes',
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options', 'view'},
        'introduced': "9.10.5",
        'topic': 'DNSSEC',
        'comment': """Causes named to send specially-formed queries once per
day to domains for which trust anchors have been
configured via trusted-keys, managed-keys,
dnssec-validation auto, or dnssec-lookaside auto.

The query name used for these queries has the
form "_ta-xxxx(-xxxx)(...)".<domain>, where each
"xxxx" is a group of four hexadecimal digits
representing the key ID of a trusted DNSSEC key.

The key IDs for each domain are sorted smallest
to largest prior to encoding.

The query type is NULL.

By monitoring these queries, zone operators will be
able to see which resolvers have been updated to trust
a new key; this may help them decide when it is safe
to remove an old one.

The default is yes.""",
    }

g_nc_keywords['try-tcp-refresh'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.5.0',
        'topic': 'transport layer',
        'zone-type': {'slave', 'mirror', 'secondary'},
        'comment': """Try to refresh the zone using TCP if UDP queries fail.
For BIND 8 compatibility, the default is yes.""",
    }

g_nc_keywords['type'] = \
    {
        # 'default': 'delegation-only',  # change from 'master' in v9.12
        'default': 'primary',  # change from 'delegation-only' in v9.13
        # 'mirror' added in v9.15
        'validity': {
            'regex': r'(delegation\-only|master|primary|slave|secondary|stub|static\-stub|hint|forward|redirect|mirror)'},
        'found-in': {'zone'},
        'zone-type': {'delegation-only', 'forward', 'hint', 'in-view', 'master', 'primary', 'redirect', 'slave',
                      'secondary',
                      'static-stub', 'stub'},
        'introduced': '8.1',
        # 'redirect' introduced in v9.9
        'topic': 'cache, caching',
        'comment': """
Option 'static-stub' added in v9.8.0.
Option 'redirect' added in v9.9.0.
Zone type may take one of the following values:

delegation-only
  Indicates only referrals (or delegations) will be issued for the zone and
  should used for TLDs only not leaf (non TLD) zones. The generation of
  referrals in leaf zones is determined by the RRs contained in it
  (see ARM Chapter 9 Delegation of Sub-domains).

forward
  A zone of type forward is simply a way to configure forwarding on a per-domain
  or per zone basis. To be effective both a forward and forwarders statement
  should be included. If no forwarders statement is present or an empty list is
  provided then no forwarding will be done for the domain canceling the effects
  of any forwarders in the options clause.

hint
  The initial set of root-servers is defined using a hint zone. When the server
  starts up it uses the hints zone file to find a root name server and get the
  most recent list of root name servers. If no hint zone is specified for class
  IN, the server uses a compiled-in default set of root servers. Classes other
  than IN have no built-in defaults hints. 'hint' zone files are covered in
  more detail under required zones.

in-view
  Not valid for the type statement but removes the need for any type
  definition. See in-view statement.

master
  The server reads the zone data direct from local storage (a zone file) and
  provides authoritative answers for the zone.

redirect
  Applicable to recursive servers (resolvers) only. Allows the user to control
  the behavior of (to redirect) an NXDOMAIN response received only from a
  non-DNSSEC (unsigned) zone (that is, the NXDOMAIN response is not signed - it is
  not a PNE response) for certain users, controlled by an allow-query statement,
  or certain zones defined in a normal zone file specified by a file statement.
  The zone files used are not visible in any normal manner (they cannot be
  explicitly queried, addressed for the purposes of zone transfer or from rndc)
  but are in all other respects normal zone files. This is a very powerful
  feature and should be used with caution. For example, if an ISP in
  Argentina wished to promote an Argentinian Registration service
  (country code .ar) then it could define the following:

// snippet from recursive named.conf
...
zone "ar" {
  type redirect;
  file "ar.zone";
  allow-query {any;}; ; all users
  ; this is not an OPEN resolver since the any
  ; applies only to NXDOMAIN responses
  ; the initial query scope (defined in the options clause)
  ; determines the OPEN/CLOSED status
};
...

; ar.zone zone file snippet
;
$ORIGIN ar.
...
; uses wildcard to soak up all responses for any .ar domain
*.ar.    A 192.168.2.3  ; web service
;OR
*.ar.    NS ns.example.ar.
...


If a web service is configured at 192.168.2.3 then it could, as an
example, return a page offering to register this domain name, or it
could simply make a benign service announcement suggesting some
corrective action, or as in the second option it could point at a
name server which could take some domain name specific action.
The scope of the zone file is essentially unlimited thus, a zone "."
clause (not to be confused with a hints file which would use type
hints; not type redirect;) would pick up all NXDOMAINs for any TLD,
whereas a zone "co.uk" clause would only pick up commercial domain
names in the UK.

Only a single redirect zone is allowed or when used with view clauses
only a single redirect per view. (Only the file, allow-query and
masterfile-format statements are allowed i redirect zone clauses.)

slave
  A slave zone is a replica of the master zone and obtains its zone
  data by zone transfer operations. The slave will respond
  authoritatively for the zone as long as it has valid (not timed
  out) zone data defined by the expiry parameter of the SOA RR.
  The mandatory masters statement specifies one or more IP addresses
  of master servers that the slave contacts to refresh or update its
  copy of the zone data. When the TTL specified by the refresh
  parameter is reached the slave will query the SOA RR from the zone
  master. If the sn paramater (serial number) is greater than the
  current value a zone tansfer is initiated. If the slave cannot
  obtain a new copy of the zone data when the SOA expiry value is
  reached then it will stop responding for the zone. Authentication
  between the zone slave and zone master can be performed with
  per-server TSIG keys (see masters statement). By default zone
  transfers are made using port 53 but this can be changed using
  the masters statement. If an optional file statement is defined
  then the zone data will be written to this file whenever the zone
  is changed and reloaded from this file on a server restart. If the
  file statement is not present then the slave cannot respond to
  zone queries until it has carried out a zone transfer, thus, if
  the zone master is unavailable on a slave load the slave cannot
  respond to queries for the zone.

static-stub
  A stub zone is similar to a slave zone except that it replicates
  only the NS records of a master zone instead of the entire zone
  (essentially providing a referral only service). Unlike Stub
  zones which take their NS RRs from the real zone master
  Static-Stub zones allow the user to configure the NS RRs
  (using server-names) or addresses (using server-addresses)
  that will be provided in the referral (overriding any valid data
  in the cache). The net effect of the static-stub is that the
  user is enabled (in a recursive resolver) to redirect a zone,
  whether for good or evil purposes is a local decision. (In
  addition to server-names and server-addresses only allow-query
  and zone-statistics statements are allowed when type static-stub;
  is present.)

stub
  A stub zone is similar to a slave zone except that it replicates
  only the NS records of a master zone instead of the entire zone
  (essentially providing a referral only service). Stub zones are
  not a standard part of the DNS they are a feature specific to
  the BIND implementation and should not be used unless there is
  a specific requirement.
""",
    }

g_nc_keywords['udp-receive-buffer'] = \
    {
        'default': 0,
        'validity': {'range': {0, 2 ** 32 - 1},
                     'string': 'unlimited'},
        'found-in': {'options'},
        'introduced': '9.18.0',
        'topic': 'TCP, buffer, resource',
        'comment': '',
    }

g_nc_keywords['udp-send-buffer'] = \
    {
        'default': 0,
        'validity': {'range': {0, 2 ** 32 - 1},
                     'string': 'unlimited'},
        'found-in': {'options'},
        'introduced': '9.18.0',
        'topic': 'TCP, buffer, resource',
        'comment': '',
    }

g_nc_keywords['update-check-ksk'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'KSK, dnssec, RRSIG',
        'zone-type': {'master', 'slave', 'primary', 'secondary'},
        'comment': """When set to the default value of yes, check the KSK
bit in each key to determine how the key should be used
when generating RRSIGs for a secure zone.

Ordinarily, zone-signing keys (that is, keys without
the KSK bit set) are used to sign the entire zone,
while key-signing keys (keys with the KSK bit set) are
only used to sign the DNSKEY RRset at the zone apex.

However, if this option is set to no, then the KSK bit
is ignored; KSKs are treated as if they were ZSKs and
are used to sign the entire zone. This is similar to
the dnssec-signzone -z command line option.

When this option is set to yes, there must be at least
two active keys for every algorithm represented in the
DNSKEY RRset: at least one KSK and one ZSK per
algorithm. If there is any algorithm for which this
requirement is not met, this option will be ignored
for that algorithm.

`update-check-ksk`: When set to "no", KSK will also
sign non-DNSKEY RRsets.  This option will go away and
key roles will be used to determine what keys sign
which RRsets (A KSK that should sign all RRsets will
have both the KSK and ZSK role and is referred to as
a CSK).""",
    }

g_nc_keywords['update-policy'] = \
    {
        'default': '',  # TODO define 'update-policy' in its entirety
        'validity': {'function': 'update_policy'},
        'found-in': {'zone'},
        'introduced': '9.0.0',
        'topic': 'dynamic zone update',
        'zone-type': {'master', 'primary'},
        'comment': """
Option "local" and "zonesub" introduced in 9.7.0.
Option "external" introduced in 9.8.0.
""",
    }

g_nc_keywords['use-alt-transfer-source'] = \
    {
        'default': 'yes',  # "{ 'view': 'no', 'other': 'yes'},  # TODO We got more conditional default values
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.3.0',
        'topic': 'transfer',
        'zone-type': {'slave', 'mirror', 'stub', 'secondary'},
        'comment': """Use the alternate transfer sources or not. If views
are specified this defaults to no otherwise it defaults
to yes (for BIND 8 compatibility).""",
    }

g_nc_keywords['use-id-pool'] = \
    {
        'default': None,
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'zone'},
        'introduced': '8.2',
        'obsoleted': '9.0.0',
        'topic': 'inert',
        'zone-type': {'master'},
        'comment': """This option is obsolete.
BIND 9 always allocates query IDs from a pool.""",
    }

g_nc_keywords['use-ixfr'] = \
    {
        'default': 'true',
        'validity': {'boolean'},
        'found-in': {'options'},
        'introduced': '8.2',
        'obsoleted': '9.8.0',
        'topic': 'inert',
        'comment': """This option is obsolete. If you need to disable IXFR 
to a particular server or servers, use 'server' clause.""",
    }

g_nc_keywords['use-queryport-pool'] = \
    {
        'default': 'no',
        'validity': {'function': 'boolean'},
        'found-in': {'options', 'view'},
        'introduced': '9.5',
        'obsoleted': '9.5.0',  # removed in 9.10.7
        'topic': 'inert, query port, pool, query, port',
        'comment': '',
    }

g_nc_keywords['use-v4-udp-ports'] = \
    {
        'default': "",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.5.0',
        'topic': 'query address, UDP',
        'comment': """If the server doesn't know the answer to a question,
it will query other name servers. querysource specifies
the address and port used for such queries. For queries
sent over IPv6, there is a separate query-source-v6
option.

If address is * (asterisk) or is omitted, a wildcard IP
address (INADDR_ANY) will be used.

If port is * or is omitted, a random port number from a
pre-configured range is picked up and will be used for
each query. The port range(s) is that specified in the
use-v4-udp-ports (for IPv4) and use-v6-udp-ports (for
IPv6) options, excluding the ranges specified in the
avoid-v4-udpports and avoid-v6-udp-ports options,
respectively.

The defaults of the query-source and query-source-v6
options are:
    query-source address * port *;
    query-source-v6 address * port *;
If use-v4-udp-ports or use-v6-udp-ports is unspecified,
named will check if the operating system provides a
programming interface to retrieve the system's default
range for ephemeral ports. If such an interface is
available, named will use the corresponding system
default range; otherwise, it will use its own defaults:
    use-v4-udp-ports { range 1024 65535; };
    use-v6-udp-ports { range 1024 65535; };
Note: make sure the ranges be sufficiently large for
security. A desirable size depends on various
parameters, but we generally recommend it contain at
least 16384 ports (14 bits of entropy).

Note also that the system's default range when used may
be too small for this purpose, and that the range may
even be changed while named is running; the new range
will automatically be applied when named is reloaded.

It is encouraged to configure use-v4-udp-ports and
usev6-udp-ports explicitly so that the ranges are
sufficiently large and are reasonably independent from
the ranges used by other applications.""",
    }

g_nc_keywords['use-v6-udp-ports'] = \
    {
        'default': "",
        'validity': {'regex': r"(yes|no)"},
        'found-in': {'options'},
        'introduced': '9.5.0',
        'topic': 'query address, UDP',
        'comment': """If the server doesn't know the answer to a question,
it will query other name servers. querysource specifies
the address and port used for such queries. For queries
sent over IPv6, there is a separate query-source-v6
option.

If address is * (asterisk) or is omitted, a wildcard IP
address (INADDR_ANY) will be used.

If port is * or is omitted, a random port number from a
pre-configured range is picked up and will be used for
each query. The port range(s) is that specified in the
use-v4-udp-ports (for IPv4) and use-v6-udp-ports (for
IPv6) options, excluding the ranges specified in the
avoid-v4-udpports and avoid-v6-udp-ports options,
respectively.

The defaults of the query-source and query-source-v6
options are:
    query-source address * port *;
    query-source-v6 address * port *;
If use-v4-udp-ports or use-v6-udp-ports is unspecified,
named will check if the operating system provides a
programming interface to retrieve the system's default
range for ephemeral ports. If such an interface is
available, named will use the corresponding system
default range; otherwise, it will use its own defaults:
    use-v4-udp-ports { range 1024 65535; };
    use-v6-udp-ports { range 1024 65535; };
Note: make sure the ranges be sufficiently large for
security. A desirable size depends on various
parameters, but we generally recommend it contain at
least 16384 ports (14 bits of entropy).

Note also that the system's default range when used may
be too small for this purpose, and that the range may
even be changed while named is running; the new range
will automatically be applied when named is reloaded.

It is encouraged to configure use-v4-udp-ports and
usev6-udp-ports explicitly so that the ranges are
sufficiently large and are reasonably independent from
the ranges used by other applications.""",
    }

g_nc_keywords['v6-bias'] = \
    {
        'default': 50,
        'validity': {'range': {0, 32767}},
        'unit': 'millisecond',
        'found-in': {'options', 'view'},
        'introduced': '9.11.0',
        'topic': 'IPv6, tuning',
        'comment': '',
    }

g_nc_keywords['validate-except'] = \
    {
        'default': '',
        'validity': 'string',
        'found-in': {'options', 'view'},
        'introduced': '9.14.0',
        'topic': 'DNSSEC',
        'comment': '',
    }

g_nc_keywords['version'] = \
    {
        'default': "",
        'validity': {'regex': r"((none)|(\w))",
                     'function': 'version_string'},
        'found-in': {'options'},
        'introduced': '8.2',
        'topic': 'privacy, server info',
        'comment': """The version the server should report via a query of the
name version.bind with type TXT, class CHAOS.

The default is the real version number of this server.
Specifying version none disables processing of the queries.""",
    }

g_nc_keywords['zero-no-soa-ttl'] = \
    {
        'default': 'yes',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.4.0',
        'topic': 'SOA, hidden-master',
        'zone-type': {'master', 'slave', 'mirror', 'primary', 'secondary'},
        'comment': """When returning authoritative negative responses to SOA
queries set the TTL of the SOA record returned in the
authority section to zero. The default is yes.""",
    }

g_nc_keywords['zero-no-soa-ttl-cache'] = \
    {
        'default': 'no',
        'validity': {'regex': r'(yes|no)'},
        'found-in': {'options', 'view'},
        'introduced': '9.4.0',
        'topic': 'SOA, hidden-master, cache, caching',
        'comment': """When caching a negative response to a SOA query set the
TTL to zero. The default is no.""",
    }

g_nc_keywords['zone-propagation-delay'] = \
    {
        'default': "",
        'validity': {'range': {0, 3660}},
        'found-in': {'dnssec-policy'},  # was in 'options' clause
        'introduced': '9.15.6',
        'topic': 'DNSSEC',
        'comment': "",
    }

g_nc_keywords['zone-statistics'] = \
    {
        'default': 'terse',
        'validity': {'regex': r'(yes|no|none|full|terse)'},
        'found-in': {'options', 'view', 'zone'},
        'introduced': '9.3.0',
        'topic': 'operating-system',
        'zone-type': {'master', 'slave', 'mirror', 'stub', 'static-stub', 'redirect', 'primary', 'secondary'},
        'comment': """If full, the server will collect statistical data on
all zones (unless specifically turned off on a per-zone
basis by specifying 'zone-statistics terse;' or
'zone-statistics none;' in the zone statement).

The default is terse, providing minimal statistics on
zones (including name and current serial number, but
not query type counters).

These statistics may be accessed via the
statistics-channel or using rndc stats, which will dump
them to the file listed in the statistics-file. See
also Section 6.4.
For backward compatibility with earlier versions of
BIND 9, the zone-statistics option can also accept
yes or no; yes has the same meaning as full. As of
BIND 9.10, no has the same meaning as none;
previously, it was the same as terse.""",
    }


class NamedConfGlobal(object):
    # Bind9 option name having a dash symbol got its dash replaced by an underscore symbol
    # a dash/minus symbol like dict() can in older Python versions (ie, valid_keywords['allow-query']).
    #
    this_version = "9.16.0"

    versioned_valid_keywords_tree = dict()  # structure of keywords for a particular version (TREE)
    versioned_keywords_dictionary = dict()  # Which keywords are declarable under what indices-keyword (FLAT)

    #    @profile
    def get_versioned_valid_kw_tree(self):
        """

        :return:
        """
        return self.versioned_valid_keywords_tree

    def is_user_defined_indices(self, token_kw):
        this_valid_kw_dict = self.versioned_keywords_dictionary[token_kw]
        if 'user-defined-indices' in this_valid_kw_dict:
            if this_valid_kw_dict['user-defined-indices']:
                return True
        return False

    #    @profile
    def is_current_version_keyword(self, token_kw):
        return token_kw in self.versioned_keywords_dictionary

    # @profile
    def _is_current_version_keyword(self, token_kw, desired_version=None):
        """
        _is_current_version_keyword - tests the given keyword to see if it is supported
                                      by a current version.
                                      For internal module use only.
                                      Use this outside of this module:
                                         flag = 'zone' in self.ncgv.versioned_keywords_dictionary
        :param token_kw: str() type containing a configuration keyword that is to be tested
                         for version applicability
        :param desired_version: an optional argument that a version is to be tested against.
                                defaults to the version supplied
                                to namedconfglobal.NamedConfGlobal(version='...') class instance
        :return: Boolean indicating whether or not the keyword argument is allowed by version number.
        """
        if type(token_kw) is not str:
            if self.debug > 5:
                print(
                    ("_is_current_version_keyword: cannot check version as '%s' argument "
                     "must be a str() type") % token_kw)
                print("_is_current_version_keyword: Argument '%s' currently is a %s type." % (token_kw, type(token_kw)))
            return False

        if token_kw not in g_nc_keywords:
            if self.debug > 5:
                print("token word '%s' cannot be found in global keyword dictionary" % token_kw)
            return False
        token_dict = g_nc_keywords[token_kw]
        # If no version is given, default to version given during this class instantiation.
        if desired_version is None:
            desired_version_int = self.this_version_int
        else:
            desired_version_int = normalize_version_int(desired_version)

        obsoleted = 99999999  # never got obsoleted
        introduced = 0  # always

        if 'obsoleted' in token_dict:
            obsoleted = normalize_version_int(token_dict['obsoleted'])
        if 'introduced' in token_dict:
            introduced = normalize_version_int(token_dict['introduced'])
        if introduced <= desired_version_int < obsoleted:
            return True
        return False

    # @profile
    def _build_ver_dict_subblock(self, this_kw1, tree_node):
        """
        _build_ver_dict_subblock is a class method that works at any point of the
                                 user-supplied configuration dictionary tree.
        :param this_kw1:  The keyword that is currently being worked on
        :param tree_node: That keyword' node of the user-supplied configuration dictionary tree
        :return:
        """
        for this_kw2 in self.versioned_keywords_dictionary:
            if not self._is_current_version_keyword(this_kw2):
                continue
            this_kw2_value = self.versioned_keywords_dictionary[this_kw2]
            if this_kw1 in this_kw2_value['found-in']:
                if self.debug > 5:
                    print("_build_ver_dict_subblock2[%s]: ['%s']['%s']" %
                          (self.this_version, this_kw1, this_kw2))
                tree_node[this_kw2] = dict()
                self._build_ver_dict_subblock(this_kw2,
                                              tree_node[this_kw2])

    # @profile
    def _build_versioned_dictionary(self):  # Need to hide this function using an underscore prefix

        # Have to build versioned dictionary firstly and then versioned hash-tree separately
        # because versioned hash-tree dictionary needs a full versioned dictionary all 100% ready
        for this_kw1 in g_nc_keywords.keys():

            # Skip all version of keywords that are outside our desired version
            if not self._is_current_version_keyword(this_kw1):
                #                print("_build_versioned_dictionary: ignoring %s" % (this_kw1))
                continue

            # Make a versioned (but smaller) dictionary of configuration keywords
            this_kw1_value = g_nc_keywords[this_kw1]
            self.versioned_keywords_dictionary[this_kw1] = this_kw1_value

            # While we are in that first loop ever, might as well do that
            # top-level configuration check.
            if 'topblock' in this_kw1_value and this_kw1_value['topblock']:
                self.versioned_valid_keywords_tree[this_kw1] = g_nc_keywords[this_kw1]
            # that is it.
        # Now we can stop using the g_nc_keywords[] dictionary
        # All keywords supported by that specific version are now in self.versioned_keyword_dictionary

        # Take the entire (versioned) dictionary and
        # glean for its related sub-keywords (also of a supported version)
        for this_kw1 in self.versioned_keywords_dictionary:

            # Start with the 'top-tier' of valid versioned dictionary
            this_kw1_value = self.versioned_keywords_dictionary[this_kw1]

            if 'topblock' in this_kw1_value and this_kw1_value['topblock']:
                if self.debug > 5:
                    print("_build_versioned_dictionary1[%s]: ['%s']" %
                          (self.this_version, this_kw1))
                self.versioned_valid_keywords_tree[this_kw1] = dict()

                self._build_ver_dict_subblock(this_kw1,
                                              self.versioned_valid_keywords_tree[this_kw1],
                                              )
        return

    #    @profile
    def __init__(self, version="9.10.3", debug=0):

        # Build version-specific keyword array
        self.this_version = version
        self.debug = debug
        self.this_version_int = normalize_version_int(version)

        # Setup a specific versioned dictionary
        self._build_versioned_dictionary()

    def get_version(self):
        # There is no 'set_version', you do that by
        # supplying a version argument
        # while instantiating a class
        # via 'nc = NamedConfGlobal("version")'
        return self.this_version

    def _get_clause_keywords(self, s_vkd):
        main_fi = {}
        for kw in self.versioned_keywords_dictionary:
            if 'found-in' in self.versioned_keywords_dictionary[kw]:
                for this_kw in self.versioned_keywords_dictionary[kw]['found-in']:
                    if this_kw == '':
                        main_fi[kw] = 1
        print('clause keywords: ', main_fi)
        return main_fi

    def print_versioned_dictionary(self):
        s_vkd = self.versioned_keywords_dictionary
        clauses_dict = self._get_clause_keywords(s_vkd)
        print("s_vkd: ", s_vkd['options'])
        # Cycle through each clauses
        for this_clause in clauses_dict:
            print("Clause: %s" % this_clause)
            for kw in s_vkd:
                if 'found-in' not in s_vkd[kw]:
                    print("ERROR: 'found-in' not found in fikw: %s" % kw)
                    continue
                if this_clause in s_vkd[kw]['found-in']:
                    print("  this_keyword: %s" % kw)

    def is_multiple_entries(self, token_kw):
        if token_kw in self.versioned_keywords_dictionary:
            crap = 'occurs-multiple-times' in self.versioned_keywords_dictionary[token_kw]
            return crap
        return False

    def search(self, search_kw, search_value):
        # Cycle through entire dictionary of a specific version
        print("Pattern: %s" % search_value)
        for global_keyword in self.versioned_keywords_dictionary:
            # see if the given search_kw is in this particular global_keyword
            if search_kw in self.versioned_keywords_dictionary[global_keyword]:
                this_keyvalue = self.versioned_keywords_dictionary[global_keyword][search_kw]
                if this_keyvalue != '':
                    matches = re.match(search_value, this_keyvalue)
                    if matches:
                        print("====\n%s" % (global_keyword))
                        comment = self.versioned_keywords_dictionary[global_keyword]['comment']
                        print("      comment:\n %s\n" % (comment))
                        # print((matches.group()))
        return


# class-less functions goes afterward at this point

def validate_master_keywords_dictionary():
    # There is no minimum presence of keywords in each entry of the g_ncg_keywords[] dict array
    # So what should I be validating?
    #
    # Maybe 'occurs-multiple-times': True/False?  We need those for traversing the objects under a token
    for this_kw in g_nc_keywords.keys():
        this_kw_value = g_nc_keywords[this_kw]
        if 'introduced' not in g_nc_keywords[this_kw]:
            print("validate_master_keywords_dictionary: 'introduced' not found in '%s' keyword." % this_kw)
            return False
        if 'topblock' not in this_kw_value:
            if 'found-in' not in g_nc_keywords[this_kw]:
                print("validate_master_keywords_dictionary: 'found-in' not found in '%s' keyword." % this_kw)
                return False
            if 'validity' not in g_nc_keywords[this_kw]:
                print("validate_master_keywords_dictionary: 'validate' not found in '%s' keyword." % this_kw)
                return False
    # print("validate_master_keywords_dictionary: validated.")
    return True


# @profile
def normalize_version_str(myobject):
    saved_bang = myobject.split('.', 3)
    saved_bang_len = len(saved_bang)
    if saved_bang_len == 1:
        if len(saved_bang[0]) == 0:
            saved_bang[0] = "0"
        myobject = saved_bang[0] + ".0.0"
    elif saved_bang_len == 2:
        myobject = saved_bang[0] + '.' + saved_bang[1] + '.0'
    elif saved_bang_len >= 3:
        myobject = saved_bang[0] + '.' + saved_bang[1] + '.' + saved_bang[2]
    return myobject


# @profile
def normalize_version_int(myobject: str) -> int:
    bang = myobject.split('.', 3)
    bang_len = len(bang)
    version = 0
    if bang_len >= 3:
        version += int(bang[2])
    if bang_len >= 2:
        version += int(bang[1]) * 100
    if bang_len >= 1:
        if bang != ['']:
            tmp_version = int(bang[0])
            version += tmp_version * 10000
    return version


def print_master_dictionary():
    print("print_master_dictionary: Keywords:")
    for this_keyword in g_nc_keywords:
        print("    %s:" % this_keyword)
    return


def get_clause_keywords():
    main_fi = {}
    for kw in g_nc_keywords:
        if 'found-in' in g_nc_keywords[kw]:
            for this_kw in g_nc_keywords[kw]['found-in']:
                if this_kw == '':
                    main_fi[kw] = 1
    print('clause keywords: ', main_fi)
    return main_fi


def print_clause_keywords(gnc_kw):
    print("gnc_kw: ", gnc_kw['options'])
    clauses_dict = get_clause_keywords()
    # Cycle through each clauses
    for this_clause in clauses_dict:
        print("Clause: %s" % this_clause)
        for kw in gnc_kw:
            if 'found-in' not in gnc_kw[kw]:
                print("ERROR: 'found-in' not found in fikw: %s" % kw)
                continue
            if this_clause in gnc_kw[kw]['found-in']:
                print("  this_keyword: %s" % kw)


def word_search(version, keyword, keyvalue):
    ws_ncg = NamedConfGlobal(version, debug=5)
    print("Version: %s" % ws_ncg.get_version())
    #    ws_ncg.print_versioned_dictionary()
    ws_ncg.search(keyword, keyvalue)


def validate():
    ncg = NamedConfGlobal(version='9.19.0', debug=5)

    valid = validate_master_keywords_dictionary()
    if valid:
        print('master keyword dictionary validated.')
    else:
        print('master keyword dictionary is not validated.')
        print_master_dictionary()

    print("##############################################")
    ## pp = PrettyPrinter(indent=4)
    ncg.print_versioned_dictionary()
    # print_clause_keywords(ncg)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="See all versions")
    parser.add_argument("-d", "--debug", help="See more debug output")
    parser.add_argument("-V", "--version", dest='prog_version', help="Show current program version")
    parser.add_argument("-v", "--bind-version", dest='bind_version', help="Set Bind9 version to use; default is 9.19")
    parser.add_argument("-t", "--test", dest='test', help="Test and validate the entire dictionary")
    parser.add_argument("-w", "--keyword", default='topic', dest='keyword', help="Keyword to search by")
    parser.add_argument("-k", "--keyvalue", default=r'\s*', dest='keyvalue', help="Keyvalue to search for")
    parser.add_argument("command", nargs='*', help="Commands like 'validate' or 'search'")
    args = parser.parse_args()

    if args.bind_version:
        version = args.bind_version
    else:
        version = '9.19.0'

    if args.keyword:
        search_keyword = args.keyword
    else:
        search_keyword = 'topic'

    if args.keyvalue:
        search_keyvalue = args.keyvalue
    else:
        search_keyvalue = '\s*'

    if args.command == "validate":
        validate()
    elif 'search' in args.command:
        word_search(version, search_keyword, search_keyvalue)
    else:
        word_search(version, search_keyword, search_keyvalue)

    print("END\n")


#####################################################################

if __name__ == "__main__":
    main()
