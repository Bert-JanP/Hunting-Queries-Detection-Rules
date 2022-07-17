# User added to sensitive group

### Defender For Endpoint

```
let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add your sensitive groups to this list
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType == "Group Membership changed"
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (SensitiveGroups)
```
### Sentinel
```
let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add your sensitive groups to this list
IdentityDirectoryEvents
| where TimeGenerated > ago(30d)
| where ActionType == "Group Membership changed"
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (SensitiveGroups)
```



