# Microsoft Teams Emoji Reactions

## Query Information

#### Description
This query lists the statistics of the Emoji reactions that have been send via Microsoft Teams

## Defender XDR
```KQL
CloudAppEvents
| where Application == "Microsoft Teams"
| where ActionType == "ReactedToMessage"
| extend Emoji = tostring(RawEventData.MessageReactionType)
| where isnotempty(Emoji)
| summarize TotalUsage = count() by Emoji
| sort by TotalUsage
```
## Sentinel
```KQL
CloudAppEvents
| where Application == "Microsoft Teams"
| where ActionType == "ReactedToMessage"
| extend Emoji = tostring(RawEventData.MessageReactionType)
| where isnotempty(Emoji)
| summarize TotalUsage = count() by Emoji
| sort by TotalUsage
```
