# The art of Knowing Your SIEM & XDR Data

This learning section was part of the Demo for ExpertsLive Netherlands 2024.

Session Title: The art of knowing your SIEM & XDR data

Session summary:
The always-increasing amount of data that security professionals deal with on a daily basis can be challenging. Questions such as 'Do I have this evidence?' and 'Where can I find this data?' can be difficult to answer. This session will answer these questions by discussing the tables you have and the (subtypes of) data included in those tables. This session will explore how you can gather the most value from your data in Sentinel & Defender For XDR with (a little bit of) KQL magic.

Security professionals often query their data to enrich incidents, hunt for suspicious activities or build new detections. By diving deeper into the context of the available data sources we will discover new detection and enrichment potentials, enabling us to discover the data within the data (such as Operations and ActionTypes). I will begin with a complete overview of all the different categories of data you have, before diving into the individual tables and their subtypes.

Knowing the ingested SIEM & XDR data helps security professionals to work more effectively because they are aware of what they have and where that is located. Furthermore, it allows you to get more out of the data due to the discovery of new data types.

Right audience: Blue/Purple Teamers, Threat Hunters, Detection Engineers, Security Engineers, SOC Analysts and Incident Responders.

# Demo Queries

## Data Queries

### List all unique sentinel tables with events (last 90 days)

#### Sentinel

```KQL
union * 
| where TimeGenerated > ago(90d) 
| distinct Type 
```

#### Defender XDR
```KQL
union withsource=TableName *
| where Timestamp > ago(90d) 
| distinct TableName
```

Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR|✅  | 

### Count all events per table

#### Sentinel

```KQL
union *  
| summarize TotalEvents = count() by Type 
```

#### Defender XDR
```KQL
union withsource=TableName *
| summarize TotalEvents = count() by TableName 
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

### Retrieve Table Schema
This query returns the schema of a table, you can change the *CloudAppEvents* table with any other table name.

```KQL
CloudAppEvents 
| getschema 
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

### Retrieve Sub-Tables
This query returns all unique tables and their actions.

#### Sentinel

```KQL
union * 
| where TimeGenerated > ago(90d) 
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType) 
| where isnotempty(Action) 
| distinct Type, Action
| sort by Type
```

#### Defender XDR
```KQL
union withsource=TableName *
| where Timestamp > ago(90d) 
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType) 
| where isnotempty(Action) 
| distinct TableName, Action
| sort by TableName
```

Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR|✅  | 

### Retrieve Sub-Tables
This query returns all unique tables, actions and how often they appear in your environment.

#### Sentinel

```KQL
union *  
| where TimeGenerated > ago(90d)  
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)  
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, Type  
```

#### Defender XDR
```KQL
union withsource=TableName *
| where Timestamp > ago(90d)  
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)  
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, TableName   
```

Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

### Retrieve top 10 most active tables

```KQL
union *
| summarize TotalEvents = count() by Type
| join kind=inner (Usage
| summarize GBs = round(sum(Quantity)/1000, 2) by DataType) on $left.Type == $right.DataType
| project DataType, TotalEvents, GBs
| top 10 by TotalEvents
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ❌ |
| Unified XDR| ✅ | 

### Retrieve top 10 least active sub-tables

##### Sentinel

```KQL
union *
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, Type
| project-rename DataType = Type
| project Action, TotalEvents, DataType
| top 10 by TotalEvents asc
```

#### Defender XDR

```KQL
union withsource=TableName *
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, TableName
| project-rename DataType = TableName
| project Action, TotalEvents, DataType
| top 10 by TotalEvents asc
```

Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

### Retrieve top 10 most active sub-tables

#### Sentinel

```KQL
union *
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, Type
| project-rename DataType = Type
| project Action, TotalEvents, DataType
| top 10 by TotalEvents desc 
```

#### Defender XDR
```KQL
union withsource=TableName *
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| summarize TotalEvents = count() by Action, TableName
| project-rename DataType = TableName
| project Action, TotalEvents, DataType
| top 10 by TotalEvents desc 
```

Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

### New sub-tables Defender For Endpoint

```KQL
let TimeFrame = 180d;
let Schedule = 7d;
let KnownActions = union DeviceEvents, DeviceFileEvents, DeviceFileCertificateInfo, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
| where Timestamp between (startofday(ago(TimeFrame)) .. startofday(ago(Schedule))) 
| where isnotempty(ActionType)
| distinct ActionType;
union withsource=TableName DeviceEvents, DeviceFileEvents, DeviceFileCertificateInfo, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
| where Timestamp > startofday(ago(Schedule)) 
| where isnotempty(ActionType) and ActionType !in (KnownActions)
| distinct TableName, ActionType
| project-rename DataType = TableName
| sort by DataType, ActionType
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

### New sub-tables Sentinel

```KQL
let TimeFrame = 180d;
let Schedule = 7d;
let KnownActions = union *
| where TimeGenerated between (startofday(ago(TimeFrame)) .. startofday(ago(Schedule))) 
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| distinct Action;
union withsource=TableName *
| where TimeGenerated > startofday(ago(Schedule)) 
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action) and Action !in (KnownActions)
| distinct TableName, Action
| project-rename DataType = TableName
| sort by DataType, Action
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ✅ |
| Unified XDR| ✅ | 

## Entity Queries

### List all tables in which entity 10.0.0.4 is found (last 90 days)
```KQL
search "10.0.0.4"
| where TimeGenerated > ago(90d)
| distinct Type
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ❌ |
| Unified XDR| ✅ | 

### List all tables in which device laptop-01.domain.tld is found (last 90 days)
```KQL
search "laptop-01.domain.tld"
| where TimeGenerated > ago(90d)
| distinct Type
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ❌ |
| Unified XDR| ✅ | 

### List all tables in which device laptop-01.domain.tld is found and how often (last 90 days)
```KQL
search "laptop-01.domain.tld"
| where TimeGenerated > ago(90d)
| summarize TotalEvents = count() by Type
```
Product Support:
| Product | Supported |
|---------| ----------|
| Sentinel | ✅ |
| Defender XDR | ❌ |
| Unified XDR| ✅ | 



