////
//// File: /etc/bind/view.red
////
//// Title: view red for the bad guy's view or public IP.
////
//// The view statement is a powerful feature of BIND 9 that 
//// lets a name server answer a DNS query differently depending 
//// on who is asking. It is particularly useful for 
//// implementing split DNS setups without having to run 
//// multiple servers.

//// Views are class specific. If no class is given, class IN is 
//// assumed. Note that all non-IN views must contain a hint 
//// zone, since only the IN class has compiled-in default hints. 

//// Zones defined within a view statement will only be 
//// accessible to clients that match the view. By defining 
//// a zone of the same name in multiple views, different 
//// zone data can be given to different clients, for 
//// example, "internal" and "external" clients in a split 
//// DNS setup. 

//// view is class dependent but the default class is IN 
//// (or 'in' - not case dependent) and has been omitted.

//// Each view statement defines a view of the DNS namespace 
//// that will be seen by a subset of clients. A client matches 
//// a view if its source IP address matches the 
//// address_match_list of the view's match-clients clause and 
//// its destination IP address matches the address_match_list of 
//// the view's match-destinations clause. If not specified, both 
//// match-clients and match-destinations default to matching all 
//// addresses. In addition to checking IP addresses 
//// match-clients and match-destinations can also take keys 
//// which provide an mechanism for the client to select the view. 
//// A view can also be specified as match-recursive-only, which 
//// means that only recursive requests from matching clients 
//// will match that view. The order of the view statements is 
//// significant a client request will be resolved in the context 
//// of the first view that it matches. 

view "red"
{
    //// match-clients
    //// A view clause matches when either or both of its match-clients 
    //// and match-destinations statements match and when the 
    //// match-recursive-only condition is met. If either or both 
    //// of match-clients and match-destinations are missing they 
    //// default to any (all hosts match). The match-clients 
    //// statement defines the address_match_list for the source 
    //// IP address of the incoming messages. Any IP which matches 
    //// will use the defined view clause. 
    //// match-clients statement may only be used in a view clause.
    match-clients { any; };

    //// A view clause matches when either or both of its match-clients 
    //// and match-destinations statements match and when the 
    //// match-recursive-only condition is met. If either or both 
    //// of match-clients and match-destinations are missing they 
    //// default to any (all hosts match). The match-destination 
    //// statement defines the address_match_list for the destination 
    //// IP address of the incoming messages. Any IP which matches 
    //// will use the defined view clause. 
    //// match-destination statement may only be used in a view clause.
    // match-destinations { any; };

    //// A view clause matches when either or both of its 
    //// match-clients and match-destinations statements match and 
    //// when the match-recursive-only condition is met. 
    //// If either or both of match-clients and match-destinations 
    //// are missing they default to any (all hosts match). 
    //// The match-recursive-only can be used in conjunction with 
    //// match-clients and match-destinations or on its own if 
    //// that is sufficient differentiation. 
    //// The default is no. 
    //// match-recursive-only statement may only be used in a view clause.
    match-recursive-only no;

    //// allow-query defines an match list of IP address(es) which are 
    //// allowed to issue queries to the server. If not specified all 
    //// hosts are allowed to make queries (defaults to allow-query {any;};).
    ////
    //// allow-query-on defines the server interface(s) from which 
    //// queries are accepted and can be useful where a server 
    //// is multi-homed, perhaps in conjunction with a view clause. 
    //// Defaults to allow-query-on {any;};) meaning that queries 
    //// are accepted on any server interface.
    //// 
    //// allow-query statements may be used in a zone, view or 
    //// a global options clause.
    allow-query {
        any;
    };

    //// Many of the options given in the options statement can also 
    //// be used within a view statement, and then apply only when 
    //// resolving queries with that view. When no view-specific 
    //// value is given, the value in the options statement is used 
    //// as a default. Also, zone options can have default values 
    //// specified in the view statement; these view-specific 
    //// defaults take precedence over those in the options 
    //// statement. 
    ////
    //// SLE says public-facing authoritative-only server (used in
    ////    hidden-master configuration or what nots) cannot do recursion.

    recursion no;

    //// allow-recursion is only relevant if recursion yes; is present 
    //// or defaulted.
    ////
    //// allow-recursion defines a address_match_list of IP address(es) 
    //// which are allowed to issue recursive queries to the server. 
    //// When allow-recursion is present allow-query-cache defaults 
    //// to the same values. If allow-recursion is NOT present the 
    //// allow-query-cache default is assumed (localnets, localhost 
    //// only). Meaning that only localhost (the server's host) and 
    //// hosts connected to the local LAN (localnets) are permitted 
    //// to issue recursive queries.
    //// 
    //// allow-recursion-on defines the server interface(s) from which 
    //// recursive queries are accepted and can be useful where a 
    //// server is multi-homed, perhaps in conjunction with a view 
    //// clause. Defaults to allow-recursion-on {any;}; meaning that 
    //// recursive queries are accepted on any server interface.
    ////
    //// NOTE: Always set 'recursion no' at global option and selectively
    //// enable 'recursion yes' in certain zones AND either with 
    //// 'allow recursion { localnets;localhost;};' on badguy/public view OR
    //// 'allow recursion { any;};' on internal/safe view.
    //// 
    //// These statements may be used in a view or a global options clause.
    ////
    //// SLE says public-facing authoritative-only server (used in
    ////    hidden-master configuration or what nots) cannot do recursion.
    // allow-recursion { none; };

    //// allow-query-cache, since BIND 9.4 allow-query-cache (or its
    //// default) controls access to the cache and thus effectively
    //// determines recursive behavior. This was done to limit the
    //// number of, possibly inadvertant, OPEN DNS resolvers.
    //// allow-query-cache defines an address_match_list of IP
    //// address(es) which are allowed to issue queries that access
    //// the local cache - without access to the local cache
    //// recursive queries are effectively useless so, in effect,
    //// this statement (or its default) controls recursive behavior.
    //// Its default setting depends on:
    ////
    ////   If recursion no; present, defaults to
    ////       allow-query-cache {none;};. No local cache access permitted.
    ////
    ////   If recursion yes; (default) then, if allow-recursion present,
    ////       defaults to the value of allow-recursion. Local cache
    ////       access permitted to the same address_match_list as
    ////       allow-recursion.
    ////
    ////   If recursion yes; (default) then, if allow-recursion is NOT
    ////       present, defaults to
    ////       allow-query-cache {localnets; localhost;};.
    ////       Locaquery-cache {localnets; localhost;};.
    ////       Local cache access permitted to localnets and localhost only.
    ////
    //// Both allow-query-cache and allow-recursion statements are allowed
    //// - this is a recipe for conflicts and a debuggers dream come true.
    //// Use either statement consistently - by preference allow-recursion.
    ////
    //// These statements may be used in a view or a global options clause.
    // allow-query-cache {
    //     localhost;
    // };

    //// allow-update may or may not be obsoleted (it wasn't in Bind 9.10)
    //// 'allow-update' on a "locally" view is essential for
    //// communication such as:
    ////    - between DHCP and BIND9
    ////    - between sftdyn and BIND9
    ////    - with a master DNS server (hidden or not)
    allow-update { 
        trusted_upstream_nameservers_acl;
    };


    /// Zone's allow-transfer is the opening
    // allow-transfer { none; };

    //// forwarders
    //// Example syntax:
    ////     forwarders { ip_addr [port ip_port] ; 
    ////                [ ip_addr [port ip_port] ; ... ] };
    ////     forwarders { 10.2.3.4; 192.168.2.5; };
    //// forwarders defines a list of IP address(es) (and optional port 
    //// numbers) to which queries will be forwarded. Only relevant when 
    //// used with the related forward statement. 
    //// This statement may be used in a zone, view or a global options clause.
    //// WARNING: badguy never needs recursion support, neither does the public
    // forwarders {
    //   208.67.222.222; # OpenDNS
    //   208.67.220.220; # OpenDNS
    // };

    //// empty-zones-enable, by default, is set to yes which means that 
    //// reverse queries for IPv4 and IPv6 addresses covered by RFCs 
    //// 1918, 4193, 5737 and 6598 (as well as IPv6 local address 
    //// (locally assigned), IPv6 link local addresses, the IPv6 
    //// loopback address and the IPv6 unknown address) but which 
    //// is not not covered by a locally defined zone clause will 
    //// automatically return an NXDOMAIN response from the local 
    //// name server. This prevents reverse map queries to such 
    //// addresses escaping to the DNS hierarchy where they are 
    //// simply noise and increase the already high level of query 
    //// pollution caused by mis-configuration. The empty-zone feature 
    //// may be turned off entirely by specifying 
    //// empty-zones-enable no; or selectively by using one or more 
    //// disable-empty-zone statements. 
    //// empty-zones-enable statement may appear in a global options 
    //// clause or a view clause.
    ////
    //// Note: An empty zone contains only an SOA and a single NS RR.
    empty-zones-enable yes;

    //// disable-empty-zone by default is set to yes which means that 
    //// reverse queries for IPv4 and IPv6 addresses covered by RFCs 
    //// 1918, 4193, 5737 and 6598 (as well as IPv6 local address 
    //// (locally assigned), IPv6 link local addresses, the IPv6 
    //// loopback address and the IPv6 unknown address) but which is 
    //// not covered by a locally defined zone clause will 
    //// automatically return an NXDOMAIN response from the local name 
    //// server. This prevents reverse map queries to such addresses 
    //// escaping to the DNS hierarchy where they are simply noise and 
    //// increase the already high level of query pollution caused by 
    //// mis-configuration. disable-empty-zone may be used to 
    //// selectively turn off empty zone responses for any particular 
    //// zone in which case the query will escape to the DNS hierarchy. 
    //// To turn off more than one empty-zone, multiple 
    //// disable-empty-zone statements must be defined. There is no 
    //// need to turn off empty-zones for which the user has defined 
    //// a local zone clause since BIND automatically detects this, 
    //// similarly if the name server forwards all queries, the 
    //// empty-zone process is automatically inhibited. Other than 
    //// name servers which delegate to the IN-ADDR.ARPA or IP6.ARPA 
    //// domains, it is not clear who would want to use this statement. 
    //// Perhaps more imaginative readers can see uses. 
    //// disable-empty-zone statement may appear in a global options 
    //// clause or a view clause.
    //// 
    //// Note: An empty zone contains only an SOA and a single NS RR.
    disable-empty-zone yes;

    //// Consider adding the 1918 zones here, if they are not used in your
    //// organization.
    //// WARNING: Badguys should not use your DNS server to resolve localhost
    //// include "/etc/bind/zones.rfc1918";
    //// include "/etc/bind/named.conf.default-zones";


    //// Zone files are optional for slave nameservers, but strongly 
    //// recommended otherwise the slave will lose all knowledge of 
    //// the zone content whenever it is restarted. It will not then 
    //// be able to start serving the zone again until it has 
    //// performed a zone transfer, and if the master is unavailable 
    //// for any reason then the period of downtime could be 
    //// substantial.
    zone "egbert.net" IN 
    {
        //// type master is the server reads the zone data direct from 
        //// local storage (a zone file) and provides authoritative 
        //// answers for the zone.
        type slave;

        //// file statement defines the file used by the zone in 
        //// quoted string format, for instance, "slave/example.com" - 
        //// or whatever convention you use. The file entry is 
        //// mandatory for master and hint and 
        //// optional - but highly recommended - for slave and 
        //// not required for forward zones. 
        //// The file may be an absolute path or relative to directory.
        ////
        //// Note: If a type Slave has a file statement then any zone 
        //// transfer will cause it to update this file. If the slave 
        //// is reloaded then it will read this file and immediately 
        //// start answering queries for the domain. If no file is 
        //// specified it will immediately try to contact the Master 
        //// and initiate a zone transfer. For obvious reasosn the 
        //// Slave cannot to zone queries until this zone transfer 
        //// is complete. If the Master is not available or the Slave 
        //// fails to contact the Master, for whatever reason, the 
        //// zone may be left with no effective Authoritative Name Servers.
        file "/var/lib/bind/zone.egbert.net";

        key-directory "/etc/bind/keys";

        //// allow-update defines an address_match_list of hosts that 
        //// are allowed to submit dynamic updates for master zones, 
        //// and thus this statement enables Dynamic DNS. The default 
        //// in BIND 9 is to disallow updates from all hosts, that is, 
        //// DDNS is disabled by default. This statement is mutually 
        //// exclusive with update-policy and applies to master zones 
        //// only. The example shows DDNS for three zones: the first 
        //// disables DDNS explicitly, the second uses an IP-based 
        //// list, and the third references a key clause. The 
        //// allow-update in the first zone clause could have been 
        //// omitted since it is the default behavior. 
        //// Many people like to be cautious in case the default mode changes.
        ////     allow-update {none;}; // no DDNS by default
        ////     allow-update {10.0.1.2;}; // DDNS this host only
        ////     allow-update {key "update-key";};
        //// In the example.org zone, the reference to the key clause 
        //// "update-key" implies that the application that performs 
        //// the update, say nsupdate, is using TSIG and must also 
        //// have the same shared secret with the same key-name. 
        //// allow-update statement may be used in a zone, view or an 
        //// options clause.
        // allow-update { none; };

        journal "/var/cache/bind/zone.egbert.net.jnl";

        //// update-policy is detailed in 
        //// http://www.zytrax.com/books/dns/ch7/xfer.html#update-policy
        //// SLE: no need to modify this local zone database, from
        //// either locally or remotely.  We use xfer-in for this.
        //update-policy { grant "local-ddns" name arca.egbert.net A; };

        //// allow-transfer defines a match list e.g. IP address(es) 
        //// that are allowed to transfer (copy) the zone information 
        //// from the server (master or slave for the zone). 
        //// The default behaviour is to allow zone transfers to any host. 
        //// While on its face this may seem an excessively friendly 
        //// default, DNS data is essentially public (that's why its 
        //// there) and the bad guys can get all of it anyway. 
        //// However if the thought of anyone being able to transfer 
        //// your precious zone file is repugnant, or (and this is 
        //// far more significant) you are concerned about possible 
        //// DoS attack initiated by XFER requests, then use the 
        //// following policy.
        allow-transfer { 
            // TODO: when the key works, comment out 'trusted_downstream_nameservers_acl'
            /// trusted_downstream_nameservers_acl;
            /// allow-transfer { !{ !localnets; any; }; key host1-host2. ;};
            key public-master-to-public-secondary;
            none;
            };

        inline-signing yes;
        auto-dnssec maintain;

        // To preserve 'Stealth' of hidden master, the 
        // option 'masters' cannot be used ... somehow
        //  There are three points to address if ns1 is to act as 
        //  a slave to ns0:
        //  
        //  ns1 must be configured to act as a slave nameserver for the zone.
        //  ns1 must be told when to perform a zone transfer. The preferred 
        //      method for ns0 to send it a notification whenever a 
        //      transfer is needed.
        //  ns0 must be configured to allow zone transfers to ns1.
        masters { 
            masters_list_upstream_nameservers;
        };

        //  Notify other secondary DNS located downstream
        notify explicit;
        also-notify { masters_list_downstream_nameserver2; };

        // allow-notify ACL specifies which hosts may send 
        // NOTIFY messages to inform this server of changes 
        // to zones for which it is acting as a secondary 
        // server. This is only applicable for secondary 
        // zones (i.e., type secondary or slave).
        //
        // If this option is set in view or options, it is 
        // globally applied to all secondary zones. If set in the 
        // zone statement, the global value is overridden.
        //
        // If not specified, the default is to process NOTIFY 
        // messages only from the configured masters for the zone. 
        // allow-notify can be used to expand the list of 
        // permitted hosts, not to reduce it.

        // Explicitly specify whom this slave should listen to
        // and not let this slave' 'masters' list determine whom.
        allow-notify { 
            trusted_upstream_nameservers_acl;
            };
    };


    //  Ask someone else to map reverse IP to ns1.egbert.net
};

