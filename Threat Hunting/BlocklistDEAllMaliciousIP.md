Blocklist.de All IP addresses that have attacked one of our customers/servers in the last 48 hours
----------
    let ThreatIntelFeed = externaldata(DestIP:
    string)[@"https://lists.blocklist.de/lists/all.txt"] with
    (format="txt", ignoreFirstRecord=True);
    let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
    let MaliciousIP = materialize (
          ThreatIntelFeed
          | where DestIP matches regex IPRegex
          | distinct DestIP
          );
    DeviceNetworkEvents
    | where RemoteIP in (MaliciousIP)

