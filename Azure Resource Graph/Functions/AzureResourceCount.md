# Function: ResourcesCount()

## Query Information

#### Description
Count the number of Azure Resources for each subscription.

#### References
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?tabs=azure-portal

## Log Analytics (Sentinel)
```
let ResourcesCount = () {
    arg("").Resources
    | summarize TotalResources = count() by subscriptionId
};
ResourcesCount()
```


