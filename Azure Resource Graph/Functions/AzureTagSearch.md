# Function: AzureTagSearch()

## Query Information

#### Description
This function returns all resources based on the *SearchTag* variable that has been used as input. Note that only the resources that your account has access to are returned. 

#### References
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview
- https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter?tabs=azure-portal

## Log Analytics (Sentinel)
```
let AzureTagSearch = (SearchTag: string) {
    arg("").Resources
    | extend StringTags = tolower(tostring(tags))
    | extend SearchTagToLower = SearchTag
    | where StringTags has SearchTagToLower
    | project tags, type, name, kind, resourceGroup
};
AzureTagSearch("Test")
```


