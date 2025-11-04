# AutoIR High Impact Alert

## Query Information

#### Description
This rule can be deployed in your environment as NRT rule to deal with high severity alerts. This detection can be mapped against the response actions to always contain an incident when Ransomware, Hands-on-keyboard or RunMRU is mentioned in the commandline. This rule can help to reduce the time to contain.

Only implement this if you are sure that the rules in the list will not cause business impact on legitimate activities (or at least have a 90% or above TP ratio).

#### Risk
High alerts do not always take action to contain an incident. This rule helps to map it against response actions to reduce the time to contain.

#### References
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-take-action?view=o365-worldwide


## Defender XDR
```KQL
AlertEvidence 
| where EntityType in ('Machine', 'user')
| where Title has_any ('Ransomware', 'Hands-on-keyboard', 'RunMRU')
| where Severity == 'High'
| project-reorder Timestamp, Title, AlertId, Severity, DeviceId, DeviceName, AccountObjectId
```