# Detect the amount of ASR events that have been triggered for each device 

## Query Information

#### Description
This query gives an overview of the amount of ASR triggers for each device. A high amount of triggers can indicate that suspicious activities are performed on a device. Both audited and blocked events are listed. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide

## Defender XDR
```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```
## Sentinel
```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```
