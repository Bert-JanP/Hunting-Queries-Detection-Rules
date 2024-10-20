# List Automatically Closed Incidents

## Query Information

#### Description
List the incidents that are automatically closed by Microsoft Defender XDR. It is good practice to get an overview of the automatically closed incidents and review them once every x period to determine if all the risks have been covered. The amount of automatically closed incidents depend on the Automation levels in automated investigation and remediation capabilities that are set in your tenant.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/automation-levels?view=o365-worldwide

## Sentinel
```KQL
SecurityIncident
| where ProviderName == "Microsoft 365 Defender" and ModifiedBy == "Microsoft 365 Defender"
| extend OwnerObjectID = tostring(Owner.objectId)
| where Status == "Closed" and Classification == "Undetermined"
| where isempty(OwnerObjectID)
| where isnotempty(ClassificationComment)
```
