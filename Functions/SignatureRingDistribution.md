# Function: SignatureRingDistribution()

## Query Information

#### Description
This function returns the Signature Ring Distribution for the gradual rollout of AvPlatformRing, AvSignatureRing and AvEngineRing. The function can be called using one of these parameters to return the total devices and their rollout configuration.

#### References
- https://learn.microsoft.com/en-us/defender-endpoint/manage-gradual-rollout


## Defender XDR
```
let SignatureRingDistribution = (RingName:string) { 
    DeviceTvmInfoGathering
    | extend AvSignatureRing = tostring(parse_json(AdditionalFields).AvSignatureRing), AvPlatformRing = tostring(parse_json(AdditionalFields).AvPlatformRing), AvEngineRing = tostring(parse_json(AdditionalFields).AvEngineRing)
    | summarize TotalDevices = dcount(DeviceId) by column_ifexists(RingName, "AvSignatureRing")
    | extend RingDescription = case(
        column_ifexists(RingName, "AvSignatureRing") == "1", "Beta Channel - Prerelease",
        column_ifexists(RingName, "AvSignatureRing") == "2", "Current Channel (Preview)",
        column_ifexists(RingName, "AvSignatureRing") == "3", "Current Channel (Staged)",
        column_ifexists(RingName, "AvSignatureRing") == "4", "Current Channel (Broad)",
        column_ifexists(RingName, "AvSignatureRing") == "5", "Critical: Time Delay",
        "Unknown Ring")
    | project RingDescription, TotalDevices
    | render piechart
};
//SignatureRingDistribution("AvPlatformRing")
SignatureRingDistribution("AvSignatureRing")
//SignatureRingDistribution("AvEngineRing")
```

