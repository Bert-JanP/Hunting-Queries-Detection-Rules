# AzureHound Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087.004 | Account Discovery: Cloud Account | https://attack.mitre.org/techniques/T1087/004/ |
| T1069.003| Permission Groups Discovery: Cloud Groups | https://attack.mitre.org/techniques/T1069/003/ |

#### Description
The query below uses the *MicrosoftGraphActivityLogs* to collect potential AzureHound executions. This is done by filtering on GET requests with status 200 since AzureHound is a collector is submits GET requests to retrieve the data. Furthermore, statistics are applied to count the number of bytes retrieved and how many unique requests have been executed within the timeframe of one hour. Lastly, the stats are compared against the thresholds, if the results are bigger than the thresholds the results are returned and your analysis can begin. These thresholds depend on the size of your Entra ID tenant. My test environment has a limited set of accounts, thus the total amount of unique requests is limited. If your organisation has more than 1000 users, the *UniqueRequestThreshold* can easily be set above 5000.

#### Risk
An adversary executes AzureHound to get insights into your Azure Tenant

#### References
- https://github.com/BloodHoundAD/AzureHound
- https://www.cloudbrothers.info/detect-threats-microsoft-graph-logs-part-1/#azurehound
- https://kqlquery.com/posts/graphactivitylogs/

## Defender XDR
```KQL
let WhitelistedObjects = dynamic(["obj1", "obj2"]);
let UniqueRequestThreshold = 1000; // Depends on Entra ID tentant size. You can use the function 0.5 * TotalAzure Resources to get this number. KQL: arg("").Resources | count
let TotalResponseSizeTHreshold = 1000000; // Depends on Entra ID tentant size
let ResourceThreshold = 4;
let ReconResources = dynamic(["organization","groups","devices","applications","users","rolemanagement","serviceprincipals"]);
MicrosoftGraphActivityLogs
| where RequestMethod == "GET"
| where ResponseStatusCode == 200
| extend ParsedUri = tostring(parse_url(RequestUri).Path)
| extend GraphAPIPath = tolower(replace_string(ParsedUri, "//", "/"))
| extend GraphAPIResource = tostring(split(GraphAPIPath, "/")[2])
| where GraphAPIResource in (ReconResources)
| extend ObjectId = coalesce(UserId, ServicePrincipalId)
// Filter whitelist
| where not(ObjectId in (WhitelistedObjects))
| summarize TotalResponseSize = sum(ResponseSizeBytes), UniqueRequests = dcount(RequestId), Requests = make_set(RequestUri, 1000), Paths = make_set(GraphAPIPath), Resources = make_set(GraphAPIResource), UniqueResourceCount = dcount(GraphAPIResource) by UserId, bin(TimeGenerated, 1h), UserAgent, ObjectId
| where UniqueRequests >= UniqueRequestThreshold and TotalResponseSize >= TotalResponseSizeTHreshold and UniqueResourceCount >= ResourceThreshold
```
