# Supisicous Named Piped Event

## Query Information

#### Description
Named Pipes can be used to detect the execution of malicious software in your environment. Some software uses a standardized approach for Named Pipes, because of that they can serveas indicator.
The query below uses the Named Pipe list from [mthcht](https://github.com/mthcht) and takes that as dynamic input to hunt for matches in the DeviceEvents table.

#### Risk
Malicious software is executed resulting in the creation of a NapePipe.

#### References
- https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_named_pipe_list.csv
- https://github.com/mthcht/awesome-lists

## Defender XDR
```KQL
let NamedPipes = externaldata(pipe_name: string, metadata_description: string, metadata_tool:string,  metadata_category: string, metadata_link: string, metadata_priority:string, metadata_fp_risk: string, metadata_severity: string, metadata_tool_type: string, metadata_usage: string, metadata_comment: string, metadata_reference: string)[@"https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_named_pipe_list.csv"] with (format="csv", ignoreFirstRecord=True);
let StandardizedPipes = NamedPipes
    | project pipe_name = replace_string(tolower(pipe_name), "*", "");
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "NamedPipeEvent"
| where split(tolower(AdditionalFields.PipeName), "\\")[-1] has_any(StandardizedPipes)
| extend PipeName = AdditionalFields.PipeName, PipeNameChild = split(tolower(AdditionalFields.PipeName), "\\")[-1]
| project-reorder Timestamp, PipeName, DeviceName, AccountName
```

## Sentinel
```KQL
let NamedPipes = externaldata(pipe_name: string, metadata_description: string, metadata_tool:string,  metadata_category: string, metadata_link: string, metadata_priority:string, metadata_fp_risk: string, metadata_severity: string, metadata_tool_type: string, metadata_usage: string, metadata_comment: string, metadata_reference: string)[@"https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_named_pipe_list.csv"] with (format="csv", ignoreFirstRecord=True);
let StandardizedPipes = NamedPipes
    | project pipe_name = replace_string(tolower(pipe_name), "*", "");
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType == "NamedPipeEvent"
| where split(tolower(AdditionalFields.PipeName), "\\")[-1] has_any(StandardizedPipes)
| extend PipeName = AdditionalFields.PipeName, PipeNameChild = split(tolower(AdditionalFields.PipeName), "\\")[-1]
| project-reorder TimeGenerated, PipeName, DeviceName, AccountName
```