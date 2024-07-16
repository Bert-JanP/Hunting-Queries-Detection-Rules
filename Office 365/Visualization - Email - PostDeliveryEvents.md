# Post Dilivery Events

## Query Information

#### Description
This query visualizes the post dilivery events from exchange to view the status of your environment.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailpostdeliveryevents-table?view=o365-worldwide

## Defender For Endpoint
```KQL
EmailPostDeliveryEvents
| summarize TotalEvents = count() by Action
| render piechart with(title="Post Delivery Events")
```
## Sentinel
```KQL
EmailPostDeliveryEvents
| summarize TotalEvents = count() by Action
| render piechart with(title="Post Delivery Events")
```