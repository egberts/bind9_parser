//// 
//// File: view.red
////
//// view red is the bad guys view or public IP.
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
//// address_match_list of the views match-clients clause and
//// its destination IP address matches the address_match_list of
//// the views match-destinations clause. If not specified, both
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
    match-clients { any; };
    match-recursive-only no;
    allow-query { any; };

    recursion yes;  // turn that off on hidden-master

    allow-recursion {
        external_bastion_ip_acl; // that public DNS server
        external_downstream_nameservers_acl; // TODO: do we even need this?
        trusted_residential_network_all_acl;
        };


    //// no forwarders for external/red/public view
    forwarders { }; // cited here as a safety despite global setting

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
    disable-empty-zone no;

    dnssec-enable yes;

    include "/etc/bind/public/mz.example.net";

};

