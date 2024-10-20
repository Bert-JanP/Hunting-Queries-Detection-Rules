# List the triggered ASR events for each device in a pivot table

## Query Information

#### Description
This query returns a row for each device with a count for each Attack Surface Reduction trigger type. This can be used to find devices that trigger a lot of ASR rules. The reference can be used to find more information on each specific ASR rule. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide

## Defender XDR
```
DeviceEvents
| where ActionType startswith 'ASR'
| project DeviceName, ActionType
| evaluate pivot(ActionType)
```
