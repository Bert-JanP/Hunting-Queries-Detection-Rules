# Function: ListPublicIPs()

## Query Information

#### Description
List all public IPs that are returned by Azure Resource Graph. This can be used for enrichment or filtering. 

#### References
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?tabs=azure-portal

## Log Analytics (Sentinel)
```
let ListPublicIPs = arg("").Resources
| where type == "microsoft.network/publicipaddresses"
| extend ipAddress = tostring(properties.ipAddress), publicIPAllocationMethod = tostring(properties.publicIPAllocationMethod)
| where isnotempty(ipAddress)
| distinct ipAddress;
ListPublicIPs
```


