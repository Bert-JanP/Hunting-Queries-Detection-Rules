# User added to sensitive group

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts|https://attack.mitre.org/techniques/T1078/002|

#### Description
In order to gain high priviliges an adversary can add themselfs to groups with high priviliges. Those priviliges allow the adversary to perform almost every action in your environment. This query is currently only used to detect three different sensitive groups, however other (custom) groups can be added to the list with sensitive groups.

A false positive would be a account that is legitimately added to the sensitive group. 

#### Risk
A attacker has added themself to a sensitive group and can perform priviliges actions. 

#### References
- https://learn.microsoft.com/en-us/defender-for-identity/entity-tags#sensitive-entities

### Defender For Endpoint
```KQL
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
```KQL
let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add your sensitive groups to this list
IdentityDirectoryEvents
| where TimeGenerated > ago(30d)
| where ActionType == "Group Membership changed"
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (SensitiveGroups)
```



