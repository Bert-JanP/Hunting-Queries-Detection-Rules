## Ransomware Double Extention

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1486 | Data Encrypted for Impact |https://attack.mitre.org/techniques/T1486/ |

#### Description
Detects possible ransomware file changes by adding a custom extension to the encrypted files, such as ".docx.encrypted" or ".pdf.ezz". This is a technique that is used by multiple Ransomware groups, they do not change the currenct extention, but they add a new one to the current file.

A false positive could be a administrator that changes a lot of files. To avoid false positive by users, a minimum file rename count of 10 is implemented.

#### Risk
Ransomware is being deployed in your environment. 

#### References
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_rename/file_rename_win_ransomware.yml
- https://blog.cyble.com/2022/08/10/onyx-ransomware-renames-its-leak-site-to-vsop/
- https://app.any.run/tasks/d66ead5a-faf4-4437-93aa-65785afaf9e5/


## Defender XDR
```KQL
// Based on https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_rename/file_rename_win_ransomware.yml
// Add your most common file extentions in this list
let OriginalExtension = dynamic(['.pdf', '.docx', '.jpg', '.xlsx', '.pptx', '.txt']);
DeviceFileEvents
| where ActionType == "FileRenamed"
// Extract file extension
| extend PreviousFileExtension = extract("\\.([a-z])*", 0, PreviousFileName)
| extend NewFileExtension = extract(@'\.(.*)', 0, FileName)
// File extension must be changed
| where PreviousFileExtension != NewFileExtension
| where PreviousFileExtension has_any (OriginalExtension)
| extend RansomwareCheck = strcat(PreviousFileExtension, ".")
// Check if the new file extension contains a possible ransomware extension (e.g. .docx.encrypted or .pdf.ezz
| where NewFileExtension contains RansomwareCheck
// Remove duplicate file extensions to limit false positives (e.g. .pdf.pdf or .docx.docx)
| extend DuplicateExtensionCheck = split(NewFileExtension, ".")
| where tostring(DuplicateExtensionCheck[1]) != tostring(DuplicateExtensionCheck[2])
// Group by device and process to count renamed files
| summarize 
    FileCount = count(),
    RenamedFiles = make_list(FileName),
    Timestamp = arg_max(Timestamp, *) 
    by DeviceName, InitiatingProcessAccountName
// Filter for more than 10 files renamed
| where FileCount > 10
// Display results
| project-reorder
    Timestamp,
    FileCount,
    DeviceName,
    InitiatingProcessAccountName,
    RenamedFiles,
    PreviousFileExtension,
    PreviousFileName,
    NewFileExtension,
    FileName
```

## Sentinel
```KQL
// Based on https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_rename/file_rename_win_ransomware.yml
let OriginalExtension = dynamic(['.pdf', '.docx', '.jpg', '.xlsx', '.pptx', '.txt']);
DeviceFileEvents
| where ActionType == "FileRenamed"
// Extract file extension
| extend PreviousFileExtension = extract("\\.([a-z])*", 0, PreviousFileName)
| extend NewFileExtension = extract(@'\.(.*)', 0, FileName)
// File extension must be changed
| where PreviousFileExtension != NewFileExtension
| where PreviousFileExtension has_any (OriginalExtension)
| extend RansomwareCheck = strcat(PreviousFileExtension, ".")
// Check if the new file extension contains a possible ransomware extension (e.g. .docx.encrypted or .pdf.ezz
| where NewFileExtension contains RansomwareCheck
// Remove duplicate file extensions to limit false positives (e.g. .pdf.pdf or .docx.docx)
| extend DuplicateExtensionCheck = split(NewFileExtension, ".")
| where tostring(DuplicateExtensionCheck[1]) != tostring(DuplicateExtensionCheck[2])
// Group by device and process to count renamed files
| summarize 
    FileCount = count(),
    RenamedFiles = make_list(FileName),
    Timestamp = arg_max(TimeGenerated, *) 
    by DeviceName, InitiatingProcessAccountName
// Filter for more than 10 files renamed
| where FileCount > 10
// Display results
| project-reorder
    Timestamp,
    FileCount,
    DeviceName,
    InitiatingProcessAccountName,
    RenamedFiles,
    PreviousFileExtension,
    PreviousFileName,
    NewFileExtension,
    FileName
```



