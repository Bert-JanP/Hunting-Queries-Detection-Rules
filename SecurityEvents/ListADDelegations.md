# List AD Delegations

## Query Information

#### Description
This query is aimed to Monitor different types of delegation in the environment.
Delegations are a feature in Active Directory that a Service will impoersonate a user by creating a special TGS to make the user able to access a resource.
Based on how it's been configured and type of the delegation there are various ways to abuse this feature for lateral movement & privilege escalation.


## Sentinel
```
let exclusions = dynamic(["-" , "0x0"]);
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventData contains "AllowedToDelegateTo"
| extend AllData = tostring(parse_xml(EventData))
| extend DelegatedTo = parse_json(AllData)['EventData']['Data'][20]["#text"]
| where not (DelegatedTo in (exclusions))
```
