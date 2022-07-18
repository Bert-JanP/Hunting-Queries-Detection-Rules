## Detects possible ransomware file changes by adding a custom extension to the encrypted files, such as ".docx.encrypted" or ".pdf.ezz"

### Defender For Endpoint

```
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
// Display results
| project-reorder
     Timestamp,
     PreviousFileExtension,
     PreviousFileName,
     NewFileExtension,
     FileName,
     DeviceName,
     InitiatingProcessAccountName
```
### Sentinel
```
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
// Display results
| project-reorder
     TimeGenerated,
     PreviousFileExtension,
     PreviousFileName,
     NewFileExtension,
     FileName,
     DeviceName,
     InitiatingProcessAccountName
```



