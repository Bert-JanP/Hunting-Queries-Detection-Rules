# (Public) Inbound connections to a compromised device

## Query Information

#### Description
This query can be used to get a quick overview of all the inbound connections that have been accepted to a compromised device. This could indicate that the RemoteIP is used to gain access to the device itself. The query contains a filter to filter private IP addresses and to only search for public (RFC1918) addresses. 

#### References
- https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/

## Defender XDR
```
// Add the device you are investigating in the CompromisedDevice variable
let CompromisedDevice = "test.domain.tld";
let SearchWindow = 10d; //Customizable h = hours, d = days
DeviceNetworkEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
// Only list accepted inbound connections
| where ActionType == "InboundConnectionAccepted"
// Remove comment below if you only want to see inbound connections from public IP addresses.
//| where RemoteIPType == "Public"
// Enrich IP information
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, country, state
```
## Sentinel
```
// Add the device you are investigating in the CompromisedDevice variable
let CompromisedDevice = "test.domain.tld";
let SearchWindow = 10d; //Customizable h = hours, d = days
let SearchWindow = 10d; //Customizable h = hours, d = days
DeviceNetworkEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
// Only list accepted inbound connections
| where ActionType == "InboundConnectionAccepted"
// Remove comment below if you only want to see inbound connections from public IP addresses.
//| where RemoteIPType == "Public"
// Enrich IP information
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, country, state
```

