# Visualize MITRE ATT&CK Tactics on triggered Sentinel incidents

## Query Information

#### Description
This query visualizes the incidents that have been triggered for each MITRE ATT&CK Tactic. This will give an overview of the amount of incidents that have triggered for each specific tactic. 

#### References
- https://attack.mitre.org/tactics/enterprise/

## Sentinel
```KQL
SecurityIncident
// Collect last argumtent of incident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend MitreTactic = todynamic(parse_json(AdditionalData).tactics)
// Filter only on Incidents that contain Mitre Tactic
| where MitreTactic != "[]"
| mv-expand MitreTactic
| extend MitreTactic = tostring(MitreTactic)
| summarize count() by MitreTactic
| sort by count_
| render columnchart  with (title="Incidents triggered by MITRE ATT&CK Tactics", ytitle="Incidents Triggered")
```
