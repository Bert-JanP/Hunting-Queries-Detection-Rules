# Behaviour Detections

#### Description
Recently (March, 2023) Microsoft has published two new tables in the Advanced Hunting schema, those being BehaviorInfo and BehaviorEntities. This query leverages both tables to ensure the best results. The query is based on a treshold of 3 Mitre Att&ck techniques being executed. The current query can be changes to look for 3 unique techniques, by changing the TotalTechniques to UniqueTechniques. The query lists all behaviours and the entity information that could be retrieved. If you do not want to list all information, but for example only alert on a user that has performed numerous techniques, then you can comment the last 6 rows out. If you do recieve to many false positives because of single techniques, this query can help you reduce the number of FPs and only alert if multi technique incidents take place. 

#### Risk
An actor has taken over an account and performes multiple techniques to reach his goal. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-behaviorentities-table?view=o365-worldwide
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-behaviorinfo-table?view=o365-worldwide
- https://learn.microsoft.com/en-us/defender-cloud-apps/behaviors

## Defender XDR
```
let AlertThreshold = 3;
BehaviorInfo
// Display all Techniques in a row
| mv-expand todynamic(AttackTechniques)
// Summarize results to get statistics and lists
| summarize TotalTechniques = count(), Techniques = make_set(AttackTechniques), BehaviourIds = make_set(BehaviorId), arg_max(Timestamp, *) by AccountObjectId
| extend UniqueTechniques = array_length(Techniques)
// Check if the AlertThreshold is met. This can also be changed to Unique Techniques, depending on your needs.
| where TotalTechniques >= AlertThreshold
// Display all Behaviour Ids in a row and collect the entities. If you only want to alert based on the amount and not get the results yet, then the rows below can be filtered.
| mv-expand todynamic(BehaviourIds)
| extend BehaviourIdsString = tostring(BehaviourIds)
| join BehaviorEntities on $left.BehaviourIdsString == $right.BehaviorId
| project-away BehaviourIds, AccountObjectId1, AdditionalFields1, ActionType1, BehaviorId1, Categories1, DataSources1, Timestamp
| project-reorder AccountObjectId, TotalTechniques, UniqueTechniques, Techniques, Categories, Description, DetectionSource
| sort by AccountObjectId
```
## Sentinel
```
let AlertThreshold = 3;
BehaviorInfo
// Display all Techniques in a row
| mv-expand todynamic(AttackTechniques)
// Summarize results to get statistics and lists
| summarize TotalTechniques = count(), Techniques = make_set(AttackTechniques), BehaviourIds = make_set(BehaviorId), arg_max(TimeGenerated, *) by AccountObjectId
| extend UniqueTechniques = array_length(Techniques)
// Check if the AlertThreshold is met. This can also be changed to Unique Techniques, depending on your needs.
| where TotalTechniques >= AlertThreshold
// Display all Behaviour Ids in a row and collect the entities. If you only want to alert based on the amount and not get the results yet, then the rows below can be filtered.
| mv-expand todynamic(BehaviourIds)
| extend BehaviourIdsString = tostring(BehaviourIds)
| join BehaviorEntities on $left.BehaviourIdsString == $right.BehaviorId
| project-away BehaviourIds, AccountObjectId1, AdditionalFields1, ActionType1, BehaviorId1, Categories1, DataSources1, TimeGenerated
| project-reorder AccountObjectId, TotalTechniques, UniqueTechniques, Techniques, Categories, Description, DetectionSource
| sort by AccountObjectId
```
