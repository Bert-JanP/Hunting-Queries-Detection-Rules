# Nltest Discovery Activities

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1482 | Domain Trust Discovery | https://attack.mitre.org/techniques/T1482/ |

#### Description
The windows utility Nltest is known to be used by adversaries to enumerate domain trusts. This detection is based on Windows Security Event 4688 and triggers if more than 3 nltest queries are executed by a user on the same computer within 30 minutes. You can alter the variables yourself to tailor it to your environment.

In case you want to detect this behaviour with Defender For Endpoint, using the *DeviceProcessEvents* table, see: [Nltest Discovery](../Defender%20For%20Endpoint/NltestDiscovery.md)

#### Risk
Adverseries perform discovery activities on your network.

#### References
- https://attack.mitre.org/software/S0359/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)

## Sentinel
```KQL
let NLTestParameters = pack_array("dclist", "dcname", "dsgetdc", "dnsgetdc", "finduser", "domain_trusts", "dsquerydns");
let BinSize = 30m;
let Threshold = 3;
SecurityEvent
| where EventID == 4688
| where tolower(CommandLine) has "nltest.exe"
| extend ParsedCommandLine = tolower(parse_command_line(CommandLine, "windows")[1])
| where ParsedCommandLine has_any (NLTestParameters)
| summarize TotalQueries = count(), TotalUniqueQueries = dcount(CommandLine), Commands = make_set(CommandLine, 100) by Computer, Account, bin(TimeGenerated, BinSize)
| where TotalQueries >= Threshold
```
