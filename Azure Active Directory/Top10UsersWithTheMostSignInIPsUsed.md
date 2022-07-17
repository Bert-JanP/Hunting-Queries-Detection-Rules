# Top 10 users with the most ips used to succesfully sign in
----
### Sentinel
```
SigninLogs
| summarize IPsUsed = make_set(IPAddress), locations = make_set(LocationDetails) by Identity
| extend CountIP = array_length(IPsUsed)
| project-reorder CountIP
| top 10 by CountIP
```
