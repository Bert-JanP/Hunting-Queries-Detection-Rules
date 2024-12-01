# List the devices with interesting open ports

## Query Information

#### Description
List the devices with interesting open ports

The interesting ports defined in the query:
- 21: FTP
- 22: SSH/SFTP
- 25: SMTP
- 53: DNS
- 80: HTTP
- 110: POP3
- 443: HTTPS
- 1433: MSSQL
- 1434: MSSQL
- 3306: MySQL
- 8080: Alternative HTTP

## Defender XDR
```KQL
let portlist = dynamic([21, 22, 25, 53, 80, 110, 443, 1433, 1434, 3306, 8080]); //Add relevant ports in the list if needed
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (portlist)
| summarize OpenPorts = make_set(LocalPort) by DeviceName
| sort by array_length(OpenPorts)
```

## Sentinel
```KQL
let portlist = dynamic([21, 22, 25, 53, 80, 110, 443, 1433, 1434, 3306, 8080]); //Add relevant ports in the list if needed
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (portlist)
| summarize OpenPorts = make_set(LocalPort) by DeviceName
| sort by array_length(OpenPorts)
```
