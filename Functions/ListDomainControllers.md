# Function: ListDomainControllers()

## Query Information

#### Description
This function list all the domain controllers in your environment. Which might be usefull if you are not aware of the syntax to identify them, alternatively this function can also be used to build detections specifically for or filter on domain controllers.

#### References
- https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/functions/user-defined-functions
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-custom-functions?view=o365-worldwide

## Defender For Endpoint
```
// This function list all domain controllers that have been active in the last 7 days. 
let ListDomainControllers =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where LocalPort == 88
    | where LocalIPType == "FourToSixMapping"
    | distinct DeviceName;
// Example    
ListDomainControllers
```
## Sentinel
```
// This function list all domain controllers that have been active in the last 7 days. 
let ListDomainControllers =
    DeviceNetworkEvents
    | where TimeGenerated > ago(7d)
    | where LocalPort == 88
    | where LocalIPType == "FourToSixMapping"
    | distinct DeviceName;
// Example    
ListDomainControllers
```

