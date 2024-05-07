# Anomalous Amount of LDAP traffic

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087.002 | Account Discovery: Domain Account | https://attack.mitre.org/techniques/T1087/002/ |

#### Description
Adversaries can use LDAP to collect environment information. The query below can be used to detect anomalous amounts of LDAP queries from a originating device. This is done by baselining the normal amount of LDAP queries a device performs each hour. This query gives you input on which devices might need to be investigated.

Once you found a device you are interested in, simply use the [Find all the executed LDAP queries from a compromised device](../DFIR/Defender%20For%20Identity/MDI%20-%20LDAPQueriesByCompromisedDevice.md) with the devicename as input to list all the LDAP details. The LDAP queries that list al devices and/or all users are interesting when executed from a workstation.

The query uses a variety of different variables which determine the result.
- *starttime* - Determines the starting time of the search period
- *endtime* - Determines the end time of the search period
- *timeframe* - Determines the timeframe in which the amount of LDAP queries are counted. If you set this to 1 hour (1h) than a count for each hour is performed, if you set it to 1 day (1d) than a count for each day is performed and so on.
- *TotalEventsThreshold* - Determines that each device must at least have performed 1 LDAP query to be included.

Only workstations are included by default in this alert, if you also want to investigate servers, than remove the line as specified in the comments of the query.

#### Risk
An adversary has gained access to your network and performes LDAP queries to perform reconnaissance.

#### References
- https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/

## Defender For Endpoint
```
// Variables to define the anomalous behaviour
let starttime = 30d;
let endtime = 1d;
// Timeframe in which the amount of LDAP queries are counted
let timeframe = 1h;
let TotalEventsThreshold = 1;
// Collect workstation devicenames
let Workstations = DeviceInfo
    | where Timestamp > ago(30d)
    | where DeviceType == "Workstation"
    | distinct DeviceName;
// Collect LDAP statistics for each device
let TimeSeriesData = IdentityQueryEvents
    | where ActionType == "LDAP query"
    // If you want to have all devices included remove line below.
    | where DeviceName in~ (Workstations)
    | make-series PerHourCount=count() on Timestamp from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by DeviceName;
// Generate LDAP baseline for each device
let TimeSeriesAlerts=TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit')
    | mv-expand
        PerHourCount to typeof(double),
        Timestamp to typeof(datetime),
        anomalies to typeof(double),
        score to typeof(double),
        baseline to typeof(long);
TimeSeriesAlerts
| where anomalies > 0
// Baseline is the most important result, that is the avarage amount of LDAP queries executed by a device, the PerHourCount shows the deviation from this amount.
| project DeviceName, Timestamp, PerHourCount, baseline, anomalies, score
| where PerHourCount > TotalEventsThreshold
```
## Sentinel
```
// Variables to define the anomalous behaviour
let starttime = 90d;
let endtime = 1d;
// Timeframe in which the amount of LDAP queries are counted
let timeframe = 1h;
let TotalEventsThreshold = 1;
// Collect workstation devicenames
let Workstations = DeviceInfo
    | where TimeGenerated > ago(30d)
    | where DeviceType == "Workstation"
    | distinct DeviceName;
// Collect LDAP statistics for each device
let TimeSeriesData = IdentityQueryEvents
    | where ActionType == "LDAP query"
    // If you want to have all devices included remove line below.
    | where DeviceName in~ (Workstations)
    | make-series PerHourCount=count() on TimeGenerated from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by DeviceName;
// Generate LDAP baseline for each device
let TimeSeriesAlerts=TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit')
    | mv-expand
        PerHourCount to typeof(double),
        TimeGenerated to typeof(datetime),
        anomalies to typeof(double),
        score to typeof(double),
        baseline to typeof(long);
TimeSeriesAlerts
| where anomalies > 0
// Baseline is the most important result, that is the avarage amount of LDAP queries executed by a device, the PerHourCount shows the deviation from this amount.
| project DeviceName, Timestamp, PerHourCount, baseline, anomalies, score
| where PerHourCount > TotalEventsThreshold
```