# Visualization of successful PIM activiations

## Query Information

#### Description
This query visualises the PIM activation performed by accounts. A user who has used many different PIM roles may be interesting to examine. The same goes for PIM roles with high privileges. 


#### References
- https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/

## Sentinel
```
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| summarize count() by Identity
| sort by count_
| render columnchart
```
