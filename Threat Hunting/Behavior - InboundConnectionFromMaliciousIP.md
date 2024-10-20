# Threat Hunting for inbound connections from malicious IPs on internet facing devices

## Query Information

#### Description
This query leverages the internet-facing property in Defender For Endpoint logs. This information is enriched with Threat Intelligence IP information to find inbound connections on public-facing devices from suspicious IP addresses. The query only lists results if the port that is used matches the port that is open on the device. In this scenario IPSums level 4 is used, to reduce the false positive number, you could use higher levels:
- [Level 5](/TI%20Feed%20-%20MISP%20IPSum%20level%205.md) 
- [Level 6](/TI%20Feed%20-%20MISP%20IPSum%20level%206.md) 
- [Level 7](/TI%20Feed%20-%20MISP%20IPSum%20level%207.md) 
- [Level 8](/TI%20Feed%20-%20MISP%20IPSum%20level%208.md) 

The most likely false positive scenarios are inbound emails from known malicious IP addresses. The other false positive scenario are scanners, which can be flagged as malicious as they scan a lot of domains in a short time frame.

#### Risk
An adversary which uses a already flagged IP go scan your network for point of initial access, or an adversary has already gotten access to your network and uses this IP to connect to your environment.

#### References
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/discovering-internet-facing-devices-using-microsoft-defender-for/ba-p/3778975
- https://github.com/stamparm/ipsum

### Defender XDR

```
// Collect Threat Intel feed information from Ipsum (Level 4), more threat can be used. For examples see TI feeds on the page: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/Threat%20Hunting
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
       ThreatIntelFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
// Collect the last information from each device which is internet facing.
let InternetFacingInformation = DeviceInfo
| extend InternetFacingInfo  = AdditionalFields
// Parse all additional fields to queryable columns
| extend  InternetFacingReason = extractjson("$.InternetFacingReason", InternetFacingInfo, typeof(string)), InternetFacingLocalPort = extractjson("$.InternetFacingLocalPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicPort = extractjson("$.InternetFacingScannedPublicPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicIp = extractjson("$.InternetFacingScannedPublicIp", InternetFacingInfo, typeof(string)), InternetFacingLocalIp = extractjson("$.InternetFacingLocalIp", InternetFacingInfo, typeof(string)),    InternetFacingTransportProtocol=extractjson("$.InternetFacingTransportProtocol", InternetFacingInfo, typeof(string)), InternetFacingLastSeen = extractjson("$.InternetFacingLastSeen", InternetFacingInfo, typeof(datetime))
// Collect the max argument for each internet facing port
| summarize arg_max(Timestamp, *) by DeviceId, InternetFacingLocalPort
| where IsInternetFacing
| project DeviceId, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingReason;
// Collect the network related information for incomming connections
DeviceNetworkEvents
// Only display connections where an inbound connection has been accepted.
| where ActionType == 'InboundConnectionAccepted'
// Only show the devices that are internet facing, by joinint that information.
| join kind=inner InternetFacingInformation on $left.DeviceId == $right.DeviceId
// Make sure that the incomming connection is done to a port which is internet facing
| where LocalPort == InternetFacingLocalPort
// Filter on IPs that exsist in the Threat Intelligence Feed
| where RemoteIP in (MaliciousIP)
// If you do not want to see incomming SMTP (mail) actions remove the comment below
// | where LocalPort != 25
| project-rename ThreatIntelligenceIP=RemoteIP
| project-reorder Timestamp, DeviceName, ThreatIntelligenceIP, LocalPort, InitiatingProcessFileName
```
### Sentinel
```
// Collect Threat Intel feed information from Ipsum (Level 4), more threat can be used. For examples see TI feeds on the page: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main/Threat%20Hunting
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
       ThreatIntelFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
// Collect the last information from each device which is internet facing.
let InternetFacingInformation = DeviceInfo
| extend InternetFacingInfo  = dynamic_to_json(AdditionalFields)
// Parse all additional fields to queryable columns
| extend  InternetFacingReason = extractjson("$.InternetFacingReason", InternetFacingInfo, typeof(string)), InternetFacingLocalPort = extractjson("$.InternetFacingLocalPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicPort = extractjson("$.InternetFacingScannedPublicPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicIp = extractjson("$.InternetFacingScannedPublicIp", InternetFacingInfo, typeof(string)), InternetFacingLocalIp = extractjson("$.InternetFacingLocalIp", InternetFacingInfo, typeof(string)),    InternetFacingTransportProtocol=extractjson("$.InternetFacingTransportProtocol", InternetFacingInfo, typeof(string)), InternetFacingLastSeen = extractjson("$.InternetFacingLastSeen", InternetFacingInfo, typeof(datetime))
// Collect the max argument for each internet facing port
| summarize arg_max(TimeGenerated, *) by DeviceId, InternetFacingLocalPort
| where IsInternetFacing
| project DeviceId, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingReason;
// Collect the network related information for incomming connections
DeviceNetworkEvents
// Only display connections where an inbound connection has been accepted.
| where ActionType == 'InboundConnectionAccepted'
// Only show the devices that are internet facing, by joinint that information.
| join kind=inner InternetFacingInformation on $left.DeviceId == $right.DeviceId
// Make sure that the incomming connection is done to a port which is internet facing
| where LocalPort == InternetFacingLocalPort
// Filter on IPs that exsist in the Threat Intelligence Feed
| where RemoteIP in (MaliciousIP)
// If you do not want to see incomming SMTP (mail) actions remove the comment below
// | where LocalPort != 25
| project-rename ThreatIntelligenceIP=RemoteIP
| project-reorder TimeGenerated, DeviceName, ThreatIntelligenceIP, LocalPort, InitiatingProcessFileName
```





