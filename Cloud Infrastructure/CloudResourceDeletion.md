# (Mass) Cloud Resource Deletion

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1485 | Data Destruction | https://attack.mitre.org/techniques/T1485/ |

#### Description
This query can be used to detect (mass) resource deletion in your cloud environment. The query uses the *Threshold* and *BinSize* variables to trigger. The default is set to the deletion of 20 cloud resources in a timespan of 1 day, you can modify this to your needs.

#### Risk
An actor deletes multiple cloud resources to create impact.

#### References
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudauditevents-table

## Defender XDR
```KQL
let Threshold = 20;
let BinSize = 1d;
CloudAuditEvents
| where ActionType == "CloudAuditEventDelete"
| summarize TotalActions = count(), arg_max(Timestamp, *) by bin(Timestamp, BinSize), Account, DataSource
| where TotalActions > Threshold
```
