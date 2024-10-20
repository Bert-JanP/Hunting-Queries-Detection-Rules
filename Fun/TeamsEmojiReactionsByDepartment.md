# Microsoft Teams Emoji Reactions for each Department

## Query Information

#### Description
This query lists the statistics of the Emoji reactions that have been send via Microsoft Teams for each Department. 

## Defender XDR
```KQL
CloudAppEvents
| where Application == "Microsoft Teams"
| where ActionType == "ReactedToMessage"
| extend Emoji = tostring(RawEventData.MessageReactionType)
| where isnotempty(Emoji)
| project Emoji, AccountObjectId
| join kind=inner (IdentityInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by AccountObjectId
    | project AccountObjectId, Department)
    on $left.AccountObjectId == $right.AccountObjectId
| project Department, Emoji
| evaluate pivot(Department) // If you want to have the Departments on the y axis use | evaluate pivot(Emoji)
```
## Sentinel
```KQL
CloudAppEvents
| where Application == "Microsoft Teams"
| where ActionType == "ReactedToMessage"
| extend Emoji = tostring(RawEventData.MessageReactionType)
| where isnotempty(Emoji)
| project Emoji, AccountObjectId
| join kind=inner (IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | project AccountObjectId, Department)
    on $left.AccountObjectId == $right.AccountObjectId
| project Department, Emoji
| evaluate pivot(Department) // If you want to have the Departments on the y axis use | evaluate pivot(Emoji)
```
