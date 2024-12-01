# List the devices with open database ports

## Query Information

#### Description
This query lists the devices with open database ports

The database ports defined in the query:
- 1433: MSSQL
- 1434: MSSQL
- 1583: Pervasive SQL
- 3050: Firebird & Interbase
- 3306: MySQL
- 3351: Pervasive SQL
- 5432: PostgreSQL

#### References
- https://kqlquery.com/
- https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules
- example link 3

## Defender XDR
```KQL
let databaseports = dynamic([1433, 1434, 1583, 3050, 3306, 3351, 5432]);
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (databaseports)
| summarize OpenPorts = make_set(LocalPort), TotalOpenDatabasePorts = dcount(LocalPort) by DeviceName
| sort by TotalOpenDatabasePorts
```

## Sentinel
```KQL
let databaseports = dynamic([1433, 1434, 1583, 3050, 3306, 3351, 5432]);
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (databaseports)
| summarize OpenPorts = make_set(LocalPort), TotalOpenDatabasePorts = dcount(LocalPort) by DeviceName
| sort by TotalOpenDatabasePorts
```
