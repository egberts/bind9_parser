//// File: /etc/bind/sz.example.com
////
//// slave zone example.com
////
//// zone example com.net is the world-view of example.com network topology

zone "example.com" IN
{
    //// type master is the server reads the zone data direct from
    //// local storage (a zone file) and provides authoritative
    //// answers for the zone.
    //
    //  In example.com, this here is THE hidden master
    type slave;

    // 1:1 between 'masters'/slave-zonetype and 'also-notify'/master-zonetype
    masters {
        masters_list_same_nameserver;
    };

    allow-query {
        external_bastion_ip_acl;
        trusted_residential_network_acl;
    };

    allow-transfer {
        trusted_residential_network_acl;
    };

    forwarders { }; // there is no forwarding if example.com is hit, we are it.

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

    file "/var/lib/bind/internal/slave/db.example.com.slave";

    journal "/var/cache/bind/internal/example.com.slave.jnl";

    //
    // This statement may be specified in zone, view clauses or
    // in a global options clause.
    notify explicit;

    ////  auto-dnssec < allow | maintain >
    ////
    //// if auto-dnssec is not defined, you must rollover your keys
    //// as they expired... manually.
    //// if auto-dnssec is maintain option, named does rollover for you.
    //// if auto-dnssec is allow option, you must used "rndc sign"
    ////
    //// To enable automatic signing, add the auto-dnssec
    //// option to the zone statement in named.conf.
    //// auto-dnssec has two possible arguments: allow or maintain.
    ////
    //// With auto-dnssec allow, named can search the key
    //// directory for keys matching the zone, insert them
    //// into the zone, and use them to sign the zone.
    //// It will do so only when it receives an rndc sign <zonename>.
    ////
    //// auto-dnssec maintain includes the above functionality,
    //// but will also automatically adjust the zone's DNSKEY
    //// records on schedule according to the keys' timing
    //// metadata. (See dnssec-keygen(8) and dnssec-settime(8)
    //// for more information.)
    ////

    ////
    //// If keys are present in the key directory the first
    //// time the zone is loaded, the zone will be signed
    //// immediately, without waiting for an rndc sign or
    //// rndc loadkeys command. (Those commands can still be
    //// used when there are unscheduled key changes, however.)
    ////
    //// When new keys are added to a zone, the TTL is set to
    //// match that of any existing DNSKEY RRset. If there is
    //// no existing DNSKEY RRset, then the TTL will be set to
    //// the TTL specified when the key was created (using the
    //// dnssec-keygen -L option), if any, or to the SOA TTL.
    ////
    //// If you wish the zone to be signed using NSEC3 instead
    //// of NSEC, submit an NSEC3PARAM record via dynamic
    //// update prior to the scheduled publication and
    //// activation of the keys. If you wish the NSEC3 chain to
    //// have the OPTOUT bit set, set it in the flags field of
    //// the NSEC3PARAM record. The NSEC3PARAM record will not
    //// appear in the zone immediately, but it will be stored
    //// for later reference. When the zone is signed and the
    //// NSEC3 chain is completed, the NSEC3PARAM record will
    //// appear in the zone.
    ////
    //// Using the auto-dnssec option requires the zone to be
    //// configured to allow dynamic updates, by adding an
    //// allow-update or update-policy statement to the zone
    //// configuration. If this has not been done, the
    //// configuration will fail.
    ////
    //// "rndc loadkeys" requires "auto-dnssec maintain"
    ////
    //// https://kb.isc.org/docs/aa-00626#
    ////
    auto-dnssec maintain;

    //// named will periodically search the key directory for
    //// keys matching the zone, and if the keys' metadata
    //// indicates that any change should be made the zone,
    //// such as adding, removing, or revoking a key, then
    //// that action will be carried out. By default, the
    //// key directory is checked for changes every 60
    //// minutes; this period can be adjusted with the
    //// dnssec-loadkeys-interval, up to a maximum of 24
    //// hours. The rndc loadkeys forces named to check for
    //// key updates immediately.
    dnssec-loadkeys-interval 60;

    // DO NOT use inline DNSSEC signing on master, only on slave(s)
    // Taking another stab at inline signing on master. TODO
    inline-signing yes;
};

