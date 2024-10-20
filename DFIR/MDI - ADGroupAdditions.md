# AD Group Additions

## Query Information

#### Description
This query can be used to list all Active Directory group additions. The query uses 2 variables as input, the Group names on which you want to search and the timeframe used for the search. This could help in your investigation by knowing if accounts have been added to high priviliged groups in order for them to have more privileges.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts

## Defender XDR
```
let Groups = dynamic(['Domain Admins', 'GroupName2']); // Add your sensitive groups to this list
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityDirectoryEvents
| where Timestamp > (now() - SearchWindow)
| where ActionType == "Group Membership changed"
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (Groups)
```
## Sentinel
```
let Groups = dynamic(['Domain Admins', 'GroupName2']); // Add your sensitive groups to this list
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityDirectoryEvents
| where Timestamp > (now() - SearchWindow)
| where ActionType == "Group Membership changed"
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (Groups)
```
