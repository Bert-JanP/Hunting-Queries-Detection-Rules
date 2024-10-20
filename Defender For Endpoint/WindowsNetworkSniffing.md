# Windows Network Sniffing

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1040 | Network Sniffing | https://attack.mitre.org/techniques/T1040 |

#### Description
In Windows the default tool Packet Monitor can be used to capture network traffic. This traffic might contain valueble information that an attacker can use. Valueble information can be found in HTTP traffic, because it goes unencrypted over the wire.

#### Risk
Actor can use network sniffing to capture information. If data (passwords) is send unencrypted they can also be collected ans used to collect credentials.

#### References
- https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon

## Defender XDR

```
DeviceProcessEvents
| where FileName == "PktMon.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```
## Sentinel
```
DeviceProcessEvents
| where FileName == "PktMon.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
```



