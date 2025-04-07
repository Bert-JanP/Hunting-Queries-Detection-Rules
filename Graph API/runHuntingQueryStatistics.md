# Statistics Graph API runHuntingQuery 

## Query Information

#### Description
This query lists the statistics for the objects that used the *runHuntingQuery* API call using the Graph API. This can help determine which applications access your security data and identify new applications that connect to this Graph API endpoint.

#### References
- https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0&tabs=http

## Defender XDR
```KQL
MicrosoftGraphActivityLogs
| where RequestUri has "runHuntingQuery"
| extend ObjectId = coalesce(UserId, AppId)
| extend ObjectType = iff(isempty(AppId), "User", "Application")
| summarize TotalCalls = count() by ObjectId, ObjectType
```

## Sentinel
```KQL
MicrosoftGraphActivityLogs
| where RequestUri has "runHuntingQuery"
| extend ObjectId = coalesce(UserId, AppId)
| extend ObjectType = iff(isempty(AppId), "User", "Application")
| summarize TotalCalls = count() by ObjectId, ObjectType
```
