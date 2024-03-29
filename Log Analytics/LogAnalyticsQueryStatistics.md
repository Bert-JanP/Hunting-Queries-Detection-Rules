# Query Execution Statistics

## Query Information

#### Description
List the query execution statistics for your Log Analytics Workspace, this returns the *UnqiueQueryCount* and the *TotalQueriesExecuted* for each Azure Active Directory User. 
To audit the query executions the Azure Diagnostics settings for the Log Analytics Workspace need to be set, see references on how this can be implemented.

#### References
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/query-audit

## Sentinel
```KQL
LAQueryLogs
| summarize UnqiueQueryCount = dcount(QueryText), TotalQueriesExecuted = count() by AADEmail
| sort by AADEmail
```