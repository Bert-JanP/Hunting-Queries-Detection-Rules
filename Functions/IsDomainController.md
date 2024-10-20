# Function: IsDomainController()

## Query Information

#### Description
This function validates if a device is a Domain Controller. It will return true when it is a domain controller, alternatively false is returned.

#### References
- https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/functions/user-defined-functions
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-custom-functions?view=o365-worldwide

## Defender XDR
```
// This function validates if a device is a Domain Controller. It will return true when it is a domain controller, alternatively false is returned.
let IsDeviceDomainController = (DeviceNameInput: string) {
    let AllDomainControllers =
        DeviceNetworkEvents
        | where Timestamp > ago(7d)
        | where LocalPort == 88
        | where LocalIPType == "FourToSixMapping"
        | distinct DeviceName;
    DeviceNetworkEvents
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceName =~ DeviceNameInput
    | extend DomainController = iff(DeviceNameInput in~ (AllDomainControllers), true, false)
    | extend DeviceName = DeviceNameInput
    | distinct DomainController, DeviceName;
};
// Example
IsDeviceDomainController("yourdevice.tld")
```
## Sentinel
```
// This function validates if a device is a Domain Controller. It will return true when it is a domain controller, alternatively false is returned.
let IsDeviceDomainController = (DeviceNameInput: string) {
    let AllDomainControllers =
        DeviceNetworkEvents
        | where TimeGenerated > ago(7d)
        | where LocalPort == 88
        | where LocalIPType == "FourToSixMapping"
        | distinct DeviceName;
    DeviceNetworkEvents
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | where DeviceName =~ DeviceNameInput
    | extend DomainController = iff(DeviceNameInput in~ (AllDomainControllers), true, false)
    | extend DeviceName = DeviceNameInput
    | distinct DomainController, DeviceName;
};
// Example
IsDeviceDomainController("yourdevice.tld")
```

