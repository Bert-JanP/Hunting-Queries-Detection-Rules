# List oubound conhost connections

## Query Information

#### Description
List outbound conhost connections.

#### Risk
It is unexpected that conhost makes connections to external domains.

#### References
- https://kqlquery.com/
- https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules
- example link 3

## Defender XDR
```KQL
let ValidDomains = dynamic(['.microsoft.com', '.digicert.com']);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "conhost.exe"
| where not(ipv4_is_private(RemoteIP) or RemoteIP == "127.0.0.1")
| where not(RemoteUrl has_any (ValidDomains))
```
## Sentinel
```KQL
let ValidDomains = dynamic(['.microsoft.com', '.digicert.com']);
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "conhost.exe"
| where not(ipv4_is_private(RemoteIP) or RemoteIP == "127.0.0.1")
| where not(RemoteUrl has_any (ValidDomains))
```
