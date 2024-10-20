# ASR Rule Configuration

## Query Information

#### Description
This query returns a row for each device and states for every rule the configurationstate. This can help to prioritize rules that are not enabled or misconfigurations in the policy.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide

## Defender XDR
```
DeviceTvmInfoGathering
| summarize arg_max(Timestamp, DeviceId, DeviceName, AdditionalFields) by DeviceId
| extend ASRConfig = AdditionalFields.AsrConfigurationStates
| evaluate bag_unpack(ASRConfig)
```
