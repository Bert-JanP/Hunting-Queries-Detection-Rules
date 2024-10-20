# Security Log Cleared

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070.001 | Indicator Removal: Clear Windows Event Logs |https://attack.mitre.org/techniques/T1070/001/ |

#### Description
An attacker might delete the Security Log to hide the malicious activities. This rule only triggers on the deletion of the Security Events, however adversaries may also delete application, setup and system logs. The Windows Event log can become full, clearing the eventlog causes this rule to be triggered. 

#### Risk
An actor removes the security log to hide malicious activities. 

#### References
- https://content.fireeye.com/apt-41/rpt-apt41
- https://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/

## Defender XDR
```
DeviceEvents
| where ActionType == 'SecurityLogCleared'
| project Timestamp, DeviceName, ActionType
```
## Sentinel
```
DeviceEvents
| where ActionType == 'SecurityLogCleared'
| project Timestamp, DeviceName, ActionType
```
