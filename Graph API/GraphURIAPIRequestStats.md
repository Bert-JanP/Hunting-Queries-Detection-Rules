# GraphAPI URI Request Statistics

## Query Information

#### Description
Retrieving request statistics gives us the opportunity for new use cases. One can now summarize all the GraphAPI request types easily with the following query. The unique deltatokens have been removed from the data, returning a better overview of the executed requests.

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#what-data-is-available-in-the-microsoft-graph-activity-logs

## Sentinel
```KQL
MicrosoftGraphActivityLogs
| extend ParsedUri = tostring(parse_url(RequestUri).Path)
| summarize TotalRequest = count() by ParsedUri
| sort by TotalRequest
```