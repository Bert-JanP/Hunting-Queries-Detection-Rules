# GraphAPI Resource Request Statistics

## Query Information

#### Description
he requests that are executed by the Graph API are standardized, thus we can use the RequestUri to get statistics on which Resource is requested. The *{resource}* parameter is used for the resource in Microsoft Graph that you're referencing.


```
{HTTP method} https://graph.microsoft.com/{version}/{resource}?{query-parameters}
```
Source: [Use the Microsoft Graph API](https://learn.microsoft.com/en-us/graph/use-the-api)

The table below shows some examples of users, security and identity resources and the RequestUriPath associated with those requests.

|   RequestUriPath   | Resource      |
| ------------- | ------------- |
| */beta/users/microsoft.graph.delta()* | users |
|  */v1.0/security/alerts_v2* | security |
| */v1.0/identity/conditionalAccess/policies* | identity |

This line splits the *GraphAPIPath* at each */*, resulting in an array of elements. For the request */v1.0/security/alerts_v2* this array is ["","v1.0","security","alerts_v2"]. The [2] in the query selects the third element (count starts at 0) and the column *GraphAPIResource* is filled with this value. This now enables us to filter on particular resource types that are queried.

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#what-data-is-available-in-the-microsoft-graph-activity-logs

## Sentinel
```KQL
MicrosoftGraphActivityLogs
| extend ParsedUri = tostring(parse_url(RequestUri).Path)
// Normalize Data
| extend GraphAPIPath = tolower(replace_string(ParsedUri, "//", "/"))
// Extract 
| extend GraphAPIResource = tostring(split(GraphAPIPath, "/")[2])
| summarize TotalRequest = count() by GraphAPIResource
| sort by TotalRequest
```