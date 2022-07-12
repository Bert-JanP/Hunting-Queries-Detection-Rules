# Visualization of successful PIM activiations
----
### Sentinel
```
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| summarize count() by Identity
| sort by count_
| render columnchart
```
