# Function: LastPowerShellExecutions ()

## Query Information

#### Description
This function returns the last x amount of powershell executions that have been executed from a specified device. The function takes a *DeviceName* as input for which device the last executions need to be returned. The *Results* determines how many resuls are returned. Lastly the *TimeFrame* variable decides what the lookback period is. 

#### References
- https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/functions/user-defined-functions
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-custom-functions?view=o365-worldwide
- https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/scalar-data-types/timespan

## Defender For Endpoint
```
// Returns the last x amount of powershell executions based on a device and the timespan. Timespan examples can be seen in https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/scalar-data-types/timespan
let LastPowerShellExecutions = (DeviceNameInput: string, Results: int, TimeFrame: timespan) {
    DeviceProcessEvents
    | where Timestamp > ago(TimeFrame)
    | where DeviceName =~ DeviceNameInput
    // Function does by default filter system executions, if you want them included exclude the line below.
    | where not(AccountSid == "S-1-5-18")
    | where ProcessCommandLine contains "powershell"
    | top Results by Timestamp
    | project Timestamp, ActionType, ProcessCommandLine
};
// Example
LastPowerShellExecutions("devicename.tld", 100, 1d)
```
## Sentinel
```
// Returns the last x amount of powershell executions based on a device and the timespan. Timespan examples can be seen in https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/scalar-data-types/timespan
let LastPowerShellExecutions = (DeviceNameInput: string, Results: int, TimeFrame: timespan) {
    DeviceProcessEvents
    | where TimeGenerated > ago(TimeFrame)
    | where DeviceName =~ DeviceNameInput
    // Function does by default filter system executions, if you want them included exclude the line below.
    | where not(AccountSid == "S-1-5-18")
    | where ProcessCommandLine contains "powershell"
    | top Results by TimeGenerated
    | project TimeGenerated, ActionType, ProcessCommandLine
};
// Example
LastPowerShellExecutions("devicename.tld", 100, 1d)
```


