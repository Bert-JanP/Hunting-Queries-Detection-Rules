# Function: AnonymizedMicrosoftGraphActivityLogs()

## Query Information

#### Description
This function removes the Azure Ids from the MicrosoftGraphActivityLogs and replaces them with an Id of your liking. This allows you to easily share your screen without showing the particular groups/users that are being queries with the GraphApi.

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview

## Defender XDR
```KQL
let AzureIdRegex = "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
let ReplacementId = "<--AnonymizedAzureId-->";
let AnonymizedMicrosoftGraphActivityLogs = () {
    MicrosoftGraphActivityLogs
    | extend RequestUri = replace_regex(RequestUri, AzureIdRegex, ReplacementId)
};
AnonymizedMicrosoftGraphActivityLogs
```

## Sentinel
```KQL
let AzureIdRegex = "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
let ReplacementId = "<--AnonymizedAzureId-->";
let AnonymizedMicrosoftGraphActivityLogs = () {
    MicrosoftGraphActivityLogs
    | extend RequestUri = replace_regex(RequestUri, AzureIdRegex, ReplacementId)
};
AnonymizedMicrosoftGraphActivityLogs
```