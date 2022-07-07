# Detect when an device performs group policy reconnaissance that has not been performed from that device in the last 30 days
----
### Defender For Endpoint

```
let PreviousActivity = materialize (
     IdentityQueryEvents
     | where Timestamp > ago(30d)
     | where QueryType == "AllGroupPolicies"
     | summarize make_set(DeviceName)
     );
IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType == "AllGroupPolicies"
| where not(DeviceName has_any(PreviousActivity))
```
### Sentinel
```
let PreviousActivity = materialize (
     IdentityQueryEvents
     | where TimeGenerated > ago(30d)
     | where QueryType == "AllGroupPolicies"
     | summarize make_set(DeviceName)
     );
IdentityQueryEvents
| where TimeGenerated > ago(1d)
| where QueryType == "AllGroupPolicies"
| where not(DeviceName has_any(PreviousActivity))
```



