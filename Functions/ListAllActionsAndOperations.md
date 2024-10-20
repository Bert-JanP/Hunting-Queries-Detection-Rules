# Function: ListAllActionsAndOperations()

## Query Information

#### Description
If you want to get quick insight into all the ActionTypes, Operations and OperationNames in your Sentinel environment, the function below can be used. This function summarizes all different actions in different tables in a single view, which is optimal when you want to quickly know if some activities can be seen/detected in your environment.

Note: This query only works in Sentinel and **NOT** in Defender XDR, if you have Unified XDR Enabled it will also work in Defender XDR

#### References
- https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide

## Defender XDR
```
// List all ActionTypes, Operations and OperationNames in a single view. This can be used to get insight into the activities that are logged.
let ListAllActionsAndOperations = () {
union *
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| distinct Action, Type
};
// Example
ListAllActionsAndOperations
```

## Sentinel
```
// List all ActionTypes, Operations and OperationNames in a single view. This can be used to get insight into the activities that are logged.
let ListAllActionsAndOperations = () {
union *
| extend Action = coalesce(Operation, OperationName, OperationNameValue, ActionType)
| where isnotempty(Action)
| distinct Action, Type
};
// Example
ListAllActionsAndOperations
```
