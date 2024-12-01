# Visualize MITRE ATT&CK Techniques on triggered Sentinel incidents

## Query Information

#### Description
This query visualizes the incidents that have been triggered for each MITRE ATT&CK Tactic and technique. This will give an overview of the amount of techniques that have been triggered for each MITRE ATT&CK tactic. This can give an indication if specific techniques trigger a lot of incidents. 

#### References
- https://attack.mitre.org/tactics/enterprise/
- https://attack.mitre.org/

## Sentinel
```KQL
SecurityIncident
// Collect last argumtent of incident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend
     MitreTactic = todynamic(parse_json(AdditionalData).tactics),
     MitreTechnique = todynamic(parse_json(AdditionalData).techniques)
// Filter only on incidents that contain Mitre Tactic and Technique
| where MitreTactic != "[]" and MitreTechnique != "[]"
// Add a row for each MitreTactic and MitreTechnique
| mv-expand MitreTactic, MitreTechnique
| extend MitreTactic = tostring(MitreTactic), MitreTechnique = tostring(MitreTechnique)
| project MitreTactic, MitreTechnique
// Count the total incidents by tactic and technique
| summarize count() by MitreTactic, MitreTechnique
| render columnchart with (title="MITRE ATT&CK Techniques triggered by Tactic", ytitle="Total Incidents")
```
