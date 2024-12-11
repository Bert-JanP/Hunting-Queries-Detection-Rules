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
| where Timestamp > ago(24h)
| where ActionType == "NamedPipeEvent"
| extend AdditionalFields_parsed = parse_json(AdditionalFields)
| where split(tolower(AdditionalFields_parsed.PipeName), "\\")[-1] has_any(StandardizedPipes)
| extend PipeName = AdditionalFields_parsed.PipeName, PipeNameChild = split(tolower(AdditionalFields_parsed.PipeName), "\\")[-1], FileOperation = AdditionalFields_parsed.FileOperation, NamedPipeEnd = AdditionalFields_parsed.NamedPipeEnd
| project-reorder Timestamp, PipeName, FileOperation, DeviceName, AccountName, NamedPipeEnd
```

## Sentinel
```KQL
let NamedPipes = externaldata(pipe_name: string, metadata_description: string, metadata_tool:string,  metadata_category: string, metadata_link: string, metadata_priority:string, metadata_fp_risk: string, metadata_severity: string, metadata_tool_type: string, metadata_usage: string, metadata_comment: string, metadata_reference: string)[@"https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_named_pipe_list.csv"] with (format="csv", ignoreFirstRecord=True);
let StandardizedPipes = NamedPipes
    | project pipe_name = replace_string(tolower(pipe_name), "*", "");
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "NamedPipeEvent"
| where split(tolower(AdditionalFields.PipeName), "\\")[-1] has_any(StandardizedPipes)
| extend PipeName = AdditionalFields.PipeName, PipeNameChild = split(tolower(AdditionalFields.PipeName), "\\")[-1], FileOperation = AdditionalFields.FileOperation, NamedPipeEnd = AdditionalFields.NamedPipeEnd
| project-reorder TimeGenerated, PipeName, FileOperation, DeviceName, AccountName, NamedPipeEnd
```
