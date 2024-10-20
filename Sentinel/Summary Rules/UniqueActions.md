# Summary Rules - Unique Actions

## Query Information

#### Description
This summary rule saves all unique actions and how often they appear in your environment to the custom table or your choice.

This allows for easy retrieval of statistics and trends on how many unique actions are found in the environment each day.

**Recommended Schedule:** 24 hours.

**Recommended Delay:** 60 minutes.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/summary-rules
- https://kqlquery.com/posts/sentinel-summary-rules/

## Sentinel
```KQL
union * 
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType) 
| where isnotempty(Action) 
| summarize TotalEvents = count() by Type, Action
| extend RetrievalDate = StartDate
| sort by Type
```
