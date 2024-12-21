# Tor Connections

## Query Information

#### Description
While Tor has legitimate uses for protecting personal privacy and circumventing censorship, it is often unwanted that connections are being made to Tor nodes. Detecting connections to Tor nodes can be done using the dynamic IP list of Tor nodes provided by [dan.me.uk](https://www.dan.me.uk/), this will allow you to query the most recent nodes each time the query is executed.

#### Risk
Explain what risk this detection tries to cover

#### References
- https://www.dan.me.uk/

## Defender XDR
```KQL
let TorNodes = externaldata(IP:string )[@"https://www.dan.me.uk/Torlist/?full"] with (format="txt", ignoreFirstRecord=False);
let IPs = TorNodes
 | distinct IP;
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIP in (IPs)
| project-reorder Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName,InitiatingProcessCommandLine
```

## Sentinel
```KQL
let TorNodes = externaldata(IP:string )[@"https://www.dan.me.uk/Torlist/?full"] with (format="txt", ignoreFirstRecord=False);
let IPs = TorNodes
 | distinct IP;
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIP in (IPs)
| project-reorder TimeGenerated, DeviceName, RemoteIP, InitiatingProcessAccountName,InitiatingProcessCommandLine
```