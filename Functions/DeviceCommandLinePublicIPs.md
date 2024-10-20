# Function: DeviceCommandLinePublicIPs()

## Query Information

#### Description
This function returns all public IPv4 addresses that have been seen on the commandline of the searched device. If you also want to include the remote calls that are initiated by the system account ensure that IncludeSystemExecutions is set to *true*.

#### References
- https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- https://andreafortuna.org/2017/11/27/how-a-malware-can-download-a-remote-payload-and-execute-malicious-code-in-one-line/

## Defender XDR
```
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
// Returns all commandlines that contain a public IP addres from a specific device
let DeviceCommandLinePublicIPs = (DeviceName: string, IncludeSystemExecutions: bool){
DeviceProcessEvents
| where DeviceName == DeviceName
| extend IPAddress = extract(IPRegex, 0, ProcessCommandLine)
| where not(ipv4_is_private(IPAddress))
| where not(InitiatingProcessAccountSid == "S-1-5-18" and IncludeSystemExecutions == false)
| project Timestamp, ProcessCommandLine, IPAddress
| sort by Timestamp
};
// Example
DeviceCommandLinePublicIPs("devicename.tld", false)
```
## Sentinel
```
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
// Returns all commandlines that contain a public IP addres from a specific device
let DeviceCommandLinePublicIPs = (DeviceName: string, IncludeSystemExecutions: bool){
DeviceProcessEvents
| where DeviceName == DeviceName
| extend IPAddress = extract(IPRegex, 0, ProcessCommandLine)
| where not(ipv4_is_private(IPAddress))
| where not(InitiatingProcessAccountSid == "S-1-5-18" and IncludeSystemExecutions == false)
| project TimeGenerated, ProcessCommandLine, IPAddress
| sort by TimeGenerated
};
// Example
DeviceCommandLinePublicIPs("devicename.tld", false)
```
