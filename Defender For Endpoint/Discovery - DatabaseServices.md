# Database Disovery

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1046 | Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |

#### Description
Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Databases are a particular interest to the adversaries because they might contain sensitive data, which is valuable. This detection uses a subset of common ports that are used by a variety of database services. The threshold in the detection can be adjusted to fill your needs. Additionally, there is a list with benign devices that are allowed to connect to multiple database servers, you can add them yourself. 

The database ports defined in the query:
- 1433: MSSQL
- 1434: MSSQL
- 1583: Pervasive SQL
- 3050: Firebird & Interbase
- 3306: MySQL
- 3351: Pervasive SQL
- 5432: PostgreSQL

#### Risk
An adversary has gained access into your network and tries to find lateral movement paths or valueble information. 

#### References
- https://www2.fireeye.com/rs/848-DID-242/images/rpt-fin6.pdf
- https://securelist.com/malicious-tasks-in-ms-sql-server/92167/

## Defender XDR
```KQL
let DatabasePorts = dynamic([1433, 1434, 1583, 3050, 3306, 3351, 5432]);
// Device List with devices that perform benign connections to SQL machines
let BenignDeviceList = dynamic(['DeviceName1']);
// Threshold for the amount of unique connections
let AlertThreshold = 10;
DeviceNetworkEvents
| where ingestion_time() > ago(24h)
// Filter Database ports
| where RemotePort in (DatabasePorts)
// Filter Benign Devices
| where not(DeviceName in~(BenignDeviceList))
// Summarize results and get statistics
| summarize TotalIPsAccessed = dcount(RemoteIP), IPList = make_set(RemoteIP), PortList =  make_set(RemotePort), arg_max(Timestamp, *) by DeviceId, bin(Timestamp, 1h)
| where TotalIPsAccessed >= AlertThreshold
| project DeviceName, Timestamp, TotalIPsAccessed, IPList, PortList
```
## Sentinel
```KQL
let DatabasePorts = dynamic([1433, 1434, 1583, 3050, 3306, 3351, 5432]);
// Device List with devices that perform benign connections to SQL machines
let BenignDeviceList = dynamic(['DeviceName1']);
// Threshold for the amount of unique connections
let AlertThreshold = 10;
DeviceNetworkEvents
| where ingestion_time() > ago(24h)
// Filter Database ports
| where RemotePort in (DatabasePorts)
// Filter Benign Devices
| where not(DeviceName in~(BenignDeviceList))
// Summarize results and get statistics
| summarize TotalIPsAccessed = dcount(RemoteIP), IPList = make_set(RemoteIP), PortList =  make_set(RemotePort), arg_max(TimeGenerated, *) by DeviceId, bin(TimeGenerated, 1h)
| where TotalIPsAccessed >= AlertThreshold
| project DeviceName, TimeGenerated, TotalIPsAccessed, IPList, PortList
```



