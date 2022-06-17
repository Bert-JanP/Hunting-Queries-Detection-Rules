# Cloud App events where an anonymous proxy was used while performing activities
----
### Defender For Endpoint

```
CloudAppEvents
| where IsAnonymousProxy == 1
| project
     Timestamp,
     ActionType,
     Application,
     AccountDisplayName,
     OSPlatform,
     IPAddress,
     RawEventData


```
### Sentinel
```
CloudAppEvents
| where IsAnonymousProxy == 1
| project
     TimeGenerated,
     ActionType,
     Application,
     AccountDisplayName,
     OSPlatform,
     IPAddress,
     RawEventData


```



