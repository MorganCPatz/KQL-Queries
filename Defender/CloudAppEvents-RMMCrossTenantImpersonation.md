 // Query to potentially identify RMM Usage associated with an external Teams Call impersonating "Support"
// Detects Rmm Usage + Then Attempts to correlate affected user to an associated Teams Call with an External User
// Uses Rmm Timestamp to match against External Teams Call timeframe

let Lookback = 7d;
let RmmURLs = externaldata(URI: string)['https://raw.githubusercontent.com/jschell/RemoteManagementMonitoringTools/refs/heads/main/Network%20Indicators/RMM_SummaryNetworkURI.csv'];
let TargetUpn = DeviceNetworkEvents
| where Timestamp > ago (Lookback)
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessAccountUpn)
| where RemoteUrl has_any (RmmURLs)
| project-rename UserAccountUpn = InitiatingProcessAccountUpn, RmmTimestamp = Timestamp
| project UserAccountUpn, RmmTimestamp;
TargetUpn
| join kind=innerunique (CloudAppEvents
| where Timestamp > ago (Lookback)
| where ActionType == "CallParticipantDetail"
| where (tolower(AccountId) matches regex @"(compliance|security|help|desk|support|assistance|admin|troubleshoot|onmicrosoft.com|^tech|$tech|tech\s)")
| extend UserAccountUpn = tostring(parse_json(RawEventData.Attendees[0].UPN))
| extend UserDisplayName = parse_json(RawEventData.Attendees[0].DisplayName)
| extend JoinTime = todatetime(RawEventData.JoinTime)
| extend LeaveTime = todatetime(RawEventData.LeaveTime)
| where UserAccountUpn != AccountId
) on UserAccountUpn
| where RmmTimestamp between (JoinTime .. LeaveTime)
| project-rename ExternalId = AccountId, ExternalDisplayName = AccountDisplayName
| project Timestamp, Application, ActionType, RmmTimestamp, JoinTime, LeaveTime, UserDisplayName, UserAccountUpn, ExternalId, ExternalDisplayName


// ProcessCreation based query to potentially identify RMM Usage assocated with an External Teams Call impersonating "Support"
// Detects RMM usage + attempts to correlate target user with a Teams Call with an external user
// Can detect on RMM usage based on multiple values:  CompanyName, ProductName, or Executable
// Uses RMM Timestamp to match against External Teams Call Timeframe

let VersionInfoCompanyName = dynamic(["Ammyy", "AnyDesk Software", "Philandro Software", "Splashtop"]);
let VersionInfoProductName = dynamic(["Ammyy Admin", "Anydesk", "Atera Networks", "ConnectWise", "Continuum Managed", "ScreenConnect", "Splashtop"]);
let RmmExecutables = dynamic(["ammyy_admin.exe", "anydesk.exe", "ateraagent.exe", "quickassist.exe", "NinjaRMMAgent.exe", "NinjaRMMAgentPatcher.exe"]);
let TargetUpn = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FileName has_any (RmmExecutables) 
    or ProcessVersionInfoCompanyName has_any (VersionInfoCompanyName) 
    or ProcessVersionInfoProductName has_any(VersionInfoProductName)
| where isnotempty(InitiatingProcessAccountUpn)
| project-rename UserAccountUpn = InitiatingProcessAccountUpn, RmmTimestamp = Timestamp, RmmFileName = FileName
| project UserAccountUpn, RmmTimestamp, RmmFileName, DeviceName;
TargetUpn
| join kind=innerunique (CloudAppEvents
| where Timestamp > ago (14d)
| where ActionType == "CallParticipantDetail"
| where (tolower(AccountId) matches regex @"(compliance|security|help|desk|support|assistance|admin|troubleshoot|onmicrosoft.com|^tech|$tech|tech\s)")
| extend UserAccountUpn = tostring(parse_json(RawEventData.Attendees[0].UPN))
| extend UserDisplayName = parse_json(RawEventData.Attendees[0].DisplayName)
| extend JoinTime = todatetime(RawEventData.JoinTime)
| extend LeaveTime = todatetime(RawEventData.LeaveTime)
| where UserAccountUpn != AccountId
) on UserAccountUpn
| where RmmTimestamp between (JoinTime .. LeaveTime)
| project Timestamp, Application, ActionType, DeviceName, JoinTime, LeaveTime, UserDisplayName, UserAccountUpn, AccountId, AccountDisplayName, RmmTimestamp, RmmFileName

### Alternative DeviceNetworkEvents Query 
// Alternative query that may return FPs as it matches User RMM Activity and External Teams Call Activity
// RMM Activity taken place before or after (outside of External Calls Team) may not be related activity
// Verify activity to see if events are related
```
let Lookback = 7d;
let RmmURLs = externaldata(URI: string)['https://raw.githubusercontent.com/jschell/RemoteManagementMonitoringTools/refs/heads/main/Network%20Indicators/RMM_SummaryNetworkURI.csv'];
let TargetUpn = DeviceNetworkEvents
| where Timestamp > ago (Lookback)
| where ActionType == "ConnectionSuccess"
| where isnotempty(InitiatingProcessAccountUpn)
| where RemoteUrl has_any (RmmURLs)
| distinct InitiatingProcessAccountUpn;
CloudAppEvents
| where Timestamp > ago (Lookback)
| where ActionType == "CallParticipantDetail"
| where RawEventData.Attendees[0].UPN in (TargetUpn)
| where (tolower(AccountId) matches regex @"(compliance|security|help|desk|support|assistance|admin|troubleshoot|onmicrosoft.com|^tech|$tech|tech\s)")
| extend UserAccountUpn = parse_json(RawEventData.Attendees[0].UPN)
| extend UserDisplayName = parse_json(RawEventData.Attendees[0].DisplayName)
| extend JoinTime = todatetime(RawEventData.JoinTime)
| extend LeaveTime = todatetime(RawEventData.LeaveTime)
| where UserAccountUpn != AccountId
| project-rename ExternalId = AccountId, ExternalDisplayName = AccountDisplayName
| project Timestamp, Application, ActionType, JoinTime, LeaveTime, UserDisplayName, UserAccountUpn, ExternalId, ExternalDisplayName
```
