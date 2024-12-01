# List all GraphAPI requests of a suspicious user


## Sentinel
```KQL
let SuspiciousUserId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx";
let SearchWindow = 48h; //Customizable h = hours, d = days
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(SearchWindow)
| where UserId  == SuspiciousUserId
| lookup kind=leftouter (IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | project AccountObjectId, AccountDisplayName, AccountUPN)
    on $left.UserId == $right.AccountObjectId
| project-reorder AccountDisplayName, AccountUPN, RequestMethod, RequestUri
```



