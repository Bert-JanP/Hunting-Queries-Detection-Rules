# MDI Sensor Deleted

## Query Information

#### Description
This query returns results when a Defender For Identity Sensor has been deleted. This sensor would have been installed on your Domain Controller, ADCS, ADFS or Entra Connect server. 

#### References
- https://learn.microsoft.com/en-us/defender-for-identity/uninstall-sensor

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "SensorDeleted"
| extend Sensor = tostring(parse_json(RawEventData).ResultDescription), InitiatorUpn = tostring(parse_json(RawEventData).UserId)
| project-reorder Timestamp, Sensor, InitiatorUpn
```

## Sentinel
```KQL
CloudAppEvents
| where ActionType == "SensorDeleted"
| extend Sensor = tostring(parse_json(RawEventData).ResultDescription), InitiatorUpn = tostring(parse_json(RawEventData).UserId)
| project-reorder TimeGenerated, Sensor, InitiatorUpn
```
