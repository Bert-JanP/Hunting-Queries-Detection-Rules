# User Account Deletion

## Query Information

#### Description
Lists the deleted users based on EventId 4726.


## Sentinel
```KQL
SecurityEvent
| where EventID == 4726
| project TimeGenerated, DeletedUser = TargetAccount, Domain = TargetDomainName, Initiator = SubjectAccount, Activity 
```
