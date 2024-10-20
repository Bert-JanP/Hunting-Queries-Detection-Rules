# Internal connections made by compromised device

## Query Information

#### Description
This query list the last network connections made to each individual internal IP address. This can help to identify lateral movement, or strange connection patterns. This query only list successful connections, however failed connections could also indicate that a malicious action is performing activities. 

This query will most likely, depending on the setup of your organization always list results, since a device would communicate to Domain Controllers, Network Shares and other internal services. The network connections are enriched with the information about the remote device, namely the RemoteDevice name is known. 

This is query is aimed to be part of your inciden triage, to discover or exclude potential lateral movement in an efficient manner. 

## Defender XDR
```
// Add the device you are investigating in the CompromisedDevice variable
let CompromisedDevice = "compromiseddevice";
let SearchWindow = 48h; //Customizable h = hours, d = days
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceNetworkEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
// Only list the succesfull connections
| where ActionType == "ConnectionSuccess"
// MDE Device Discovery filter
| where InitiatingProcessFileName <> "sensendr.exe"
// Add column that identifies RFC 1918 addresses
| extend IsPrivateAddress = ipv4_is_private(RemoteIP)
// Lateral movement is mostly identified by filtering on the private ip addresses and its connections.
// This query is build to detect private IP connections and not public ip connections.
| where IsPrivateAddress == 1
// Filter System related activities performed by local service
| where InitiatingProcessAccountName != "local service"
// Only list the last connection to each IP address.
| summarize arg_max(Timestamp, *), ConnectedPorts = make_set(RemotePort) by RemoteIP
| project
     RemoteIP,
     ConnectedPorts,
     RemoteUrl,
     InitiatingProcessAccountSid,
     InitiatingProcessAccountUpn,
     CompromisedDevice = DeviceName
// Join the network info of the remote IP address, to find the devicename that belongs to that IP
| join kind=inner (DeviceNetworkInfo
     | where Timestamp > ago(SearchWindow)
     | extend IPAddres = extract(IPRegex, 0, tostring(IPAddresses))
     // See RFC 1918, these are not DHCP or Static addresses. Do leave them if you do NOT have DHCP running.
     | where not(ipv4_is_in_range(IPAddres, "169.254.0.0/16"))
     | distinct IPAddres, DeviceName)
     on $left.RemoteIP == $right.IPAddres
// Only list rows where the compromised device does not equal the RemoteDevice
| where not(CompromisedDevice  == DeviceName)
| project RemoteIP, RemoteDeviceName = DeviceName, ConnectedPorts, RemoteUrl, InitiatingProcessAccountSid, InitiatingProcessAccountUpn, CompromisedDevice
// Known false positives:
// Benign Edge Traffic, which did not initate a connection to an actual remote device.
//| where not(tostring(ConnectedPorts) == "[8009,8008]" or tostring(ConnectedPorts) == "[8008,8009]" or tostring(ConnectedPorts) == "[8009]" or tostring(ConnectedPorts) == "[8009]")
```
## Sentinel
```
// Add the device you are investigating in the CompromisedDevice variable
let CompromisedDevice = "compromiseddevice";
let SearchWindow = 48h; //Customizable h = hours, d = days
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceNetworkEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
// Only list the succesfull connections
| where ActionType == "ConnectionSuccess"
// MDE Device Discovery filter
| where InitiatingProcessFileName <> "sensendr.exe"
// Add column that identifies RFC 1918 addresses
| extend IsPrivateAddress = ipv4_is_private(RemoteIP)
// Lateral movement is mostly identified by filtering on the private ip addresses and its connections.
// This query is build to detect private IP connections and not public ip connections.
| where IsPrivateAddress == 1
// Filter System related activities performed by local service
| where InitiatingProcessAccountName != "local service"
// Only list the last connection to each IP address.
| summarize arg_max(TimeGenerated, *), ConnectedPorts = make_set(RemotePort) by RemoteIP
| project
     RemoteIP,
     ConnectedPorts,
     RemoteUrl,
     InitiatingProcessAccountSid,
     InitiatingProcessAccountUpn,
     CompromisedDevice = DeviceName
// Join the network info of the remote IP address, to find the devicename that belongs to that IP
| join kind=inner (DeviceNetworkInfo
     | where TimeGenerated > ago(SearchWindow)
     | extend IPAddres = extract(IPRegex, 0, tostring(IPAddresses))
     // See RFC 1918, these are not DHCP or Static addresses. Do leave them if you do NOT have DHCP running.
     | where not(ipv4_is_in_range(IPAddres, "169.254.0.0/16"))
     | distinct IPAddres, DeviceName)
     on $left.RemoteIP == $right.IPAddres
// Only list rows where the compromised device does not equal the RemoteDevice
| where not(CompromisedDevice  == DeviceName)
| project RemoteIP, RemoteDeviceName = DeviceName, ConnectedPorts, RemoteUrl, InitiatingProcessAccountSid, InitiatingProcessAccountUpn, CompromisedDevice
// Known false positives:
// Benign Edge Traffic, which did not initate a connection to an actual remote device.
//| where not(tostring(ConnectedPorts) == "[8009,8008]" or tostring(ConnectedPorts) == "[8008,8009]" or tostring(ConnectedPorts) == "[8009]" or tostring(ConnectedPorts) == "[8009]")
```
