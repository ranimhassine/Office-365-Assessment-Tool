#Requires -Version 5.1
<#
.SYNOPSIS
    Consultim-IT Office 365 Security Assessment Tool v1.1.0
.DESCRIPTION
    Performs a comprehensive security assessment of a Microsoft 365 tenant
    and generates an interactive HTML report with findings, scores, and recommendations.
.PARAMETER TenantId
    Tenant domain or GUID. If not provided, you will be prompted.
.PARAMETER OutputPath
    Directory to save HTML and JSON output files. Default: .\ConsultimIT-O365-Reports
.PARAMETER ReportTitle
    Custom title for the HTML report. Default: "Office 365 Security Assessment"
.PARAMETER SkipIdentity
    Skip Identity & MFA checks.
.PARAMETER SkipEmail
    Skip Email Security checks.
.PARAMETER SkipDLP
    Skip Data Protection & DLP checks.
.PARAMETER SkipTeams
    Skip Teams & SharePoint checks.
.PARAMETER SkipAudit
    Skip Audit & Monitoring checks.
.PARAMETER SkipOAuth
    Skip OAuth & App Security checks.
.PARAMETER DebugMode
    Enable verbose diagnostic tracing. Shows every API call, its result, and each
    Stats field update (old → new value) in the console. Also saves a full debug
    log file (.txt) alongside the HTML/JSON reports, and prints a zero-stats
    triage summary at the end showing which fields are still 0 and why.
    Use this flag whenever the Tenant Info tab shows all-zero stats.
.EXAMPLE
    .\ConsultimIT-O365-Assessment.ps1 -TenantId "contoso.onmicrosoft.com"
.EXAMPLE
    .\ConsultimIT-O365-Assessment.ps1 -TenantId "contoso.onmicrosoft.com" -DebugMode
.EXAMPLE
    .\ConsultimIT-O365-Assessment.ps1 -TenantId "contoso.onmicrosoft.com" -DebugMode -SkipEmail
.NOTES
    Author  : Ranim Hassine — Consultim-IT
    Version : 1.1.0
    Website : consultim-it.com
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\ConsultimIT-O365-Reports",

    [Parameter(Mandatory = $false)]
    [string]$ReportTitle = "Office 365 Security Assessment",

    [switch]$SkipIdentity,
    [switch]$SkipEmail,
    [switch]$SkipDLP,
    [switch]$SkipTeams,
    [switch]$SkipAudit,
    [switch]$SkipOAuth,

    [Parameter(Mandatory = $false)]
    [switch]$DebugMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$StartTime = Get-Date

#region ─── GLOBALS ────────────────────────────────────────────────────────────
$Script:Findings     = [System.Collections.ArrayList]::new()
$Script:GraphConnected = $false
$Script:ExoConnected   = $false
$Script:TenantDisplayName = "Unknown"
$Script:TenantId       = $TenantId
$Script:DebugLog       = [System.Collections.ArrayList]::new()
$Script:Stats = @{
    TotalUsers        = 0
    EnabledUsers      = 0
    GuestUsers        = 0
    GlobalAdmins      = 0
    StaleUsers        = 0
    MFAPct            = 0
    AdminNoMFA        = 0
    EnabledCAPolicies = 0
    DLPPolicies       = 0
    SecureScore       = 0
    MaxSecureScore    = 0
    AppRegistrations  = 0
    ServicePrincipals = 0
}
#endregion

#region ─── CONSOLE HELPERS ────────────────────────────────────────────────────
function Write-Banner {
    $banner = @"

  ╔═══════════════════════════════════════════════════════════════════╗
  ║                                                                   ║
  ║        Consultim-IT  ·  Office 365 Security Assessment           ║
  ║                          Version 1.0.0                           ║
  ║                                                                   ║
  ║        Author  : Ranim Hassine — Consultim-IT                    ║
  ║        Website : consultim-it.com                                ║
  ║                                                                   ║
  ╚═══════════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-Info    { param($msg) Write-Host "  [*] $msg" -ForegroundColor Yellow }
function Write-Success { param($msg) Write-Host "  [+] $msg" -ForegroundColor Green  }
function Write-Err     { param($msg) Write-Host "  [!] $msg" -ForegroundColor Red    }
function Write-Skip    { param($msg) Write-Host "  [-] $msg" -ForegroundColor Gray   }

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n  ══════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "   $Title" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════`n" -ForegroundColor DarkCyan
}

# ── DEBUG HELPERS ─────────────────────────────────────────────────────────────
function Write-Dbg {
    param([string]$Msg, [string]$Level = "INFO")
    if (-not $DebugMode) { return }
    $ts    = (Get-Date).ToString("HH:mm:ss.fff")
    $color = switch ($Level) {
        "OK"    { "Green"   }
        "WARN"  { "Yellow"  }
        "ERROR" { "Red"     }
        "STAT"  { "Magenta" }
        "API"   { "Cyan"    }
        default { "DarkGray"}
    }
    Write-Host "  [DBG $ts][$Level] $Msg" -ForegroundColor $color
    $null = $Script:DebugLog.Add([PSCustomObject]@{
        Time    = $ts
        Level   = $Level
        Message = $Msg
    })
}

function Set-Stat {
    <#
    .SYNOPSIS
        Sets a Stats key and emits a debug log entry showing old → new value.
        Use this instead of direct $Script:Stats.Key = Value assignments.
    #>
    param([string]$Key, $Value)
    $old = $Script:Stats[$Key]
    $Script:Stats[$Key] = $Value
    Write-Dbg "STAT  $Key : $old → $Value" -Level "STAT"
}

function Write-DebugSection {
    param([string]$Title)
    if (-not $DebugMode) { return }
    Write-Host "`n  ┌─────────────────────────────────────────────" -ForegroundColor DarkMagenta
    Write-Host "  │ DEBUG: $Title" -ForegroundColor Magenta
    Write-Host "  └─────────────────────────────────────────────" -ForegroundColor DarkMagenta
}

function Write-StatsSnapshot {
    if (-not $DebugMode) { return }
    Write-Host "`n  ┌── STATS SNAPSHOT ───────────────────────────" -ForegroundColor DarkMagenta
    foreach ($key in ($Script:Stats.Keys | Sort-Object)) {
        $val = $Script:Stats[$key]
        $flag = if ($val -eq 0) { " ◄ ZERO" } else { "" }
        $color = if ($val -eq 0) { "Yellow" } else { "Magenta" }
        Write-Host ("  │  {0,-22} = {1}{2}" -f $key, $val, $flag) -ForegroundColor $color
    }
    Write-Host "  └─────────────────────────────────────────────" -ForegroundColor DarkMagenta
}
#endregion

#region ─── FINDINGS FRAMEWORK ─────────────────────────────────────────────────
function Add-Finding {
    param(
        [string]$CheckId,
        [string]$Domain,
        [string]$Title,
        [ValidateSet("Pass","Fail","Warning","Info")]
        [string]$Status,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [ValidateSet("Critical","High","Medium","Low","Informational")]
        [string]$Severity,
        [string]$Description,
        [string]$Recommendation,
        [string]$Reference
    )
    $riskMap    = @{ Critical=5; High=4; Medium=3; Low=2; Informational=1 }
    $scoreMap   = @{ Critical=10; High=7; Medium=4; Low=2; Informational=0 }
    $null = $Script:Findings.Add([PSCustomObject]@{
        CheckId         = $CheckId
        Domain          = $Domain
        Title           = $Title
        Status          = $Status
        CurrentValue    = $CurrentValue
        ExpectedValue   = $ExpectedValue
        Severity        = $Severity
        Description     = $Description
        Recommendation  = $Recommendation
        Reference       = $Reference
        RiskScore       = $riskMap[$Severity]
        SecureScore     = if ($Status -eq "Pass") { $scoreMap[$Severity] } else { 0 }
    })
}
#endregion

#region ─── MODULE CHECK ───────────────────────────────────────────────────────
function Test-RequiredModules {
    Write-SectionHeader "Pre-flight: Module Check"
    $required = @(
        @{ Name = "Microsoft.Graph";     MinVersion = "2.0.0"; InstallCmd = "Install-Module Microsoft.Graph -Scope CurrentUser -Force" },
        @{ Name = "Microsoft.Graph.Beta";MinVersion = "2.0.0"; InstallCmd = "Install-Module Microsoft.Graph.Beta -Scope CurrentUser -Force" },
        @{ Name = "ExchangeOnlineManagement"; MinVersion = "3.0.0"; InstallCmd = "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force" }
    )
    $missing = @()
    foreach ($mod in $required) {
        $installed = Get-Module -ListAvailable -Name $mod.Name | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $installed) {
            Write-Err "Module '$($mod.Name)' is NOT installed."
            Write-Host "       Install with: $($mod.InstallCmd)" -ForegroundColor Yellow
            $missing += $mod.Name
        } else {
            Write-Success "Module '$($mod.Name)' v$($installed.Version) found."
        }
    }
    if ($missing.Count -gt 0) {
        Write-Host "`n  [?] Some modules are missing. Continue anyway? (Graph/EXO checks may be skipped) [y/N]: " -ForegroundColor Yellow -NoNewline
        $ans = Read-Host
        if ($ans -notmatch '^[Yy]') {
            Write-Err "Aborted by user."
            exit 1
        }
    }
}
#endregion

#region ─── CONNECT ─────────────────────────────────────────────────────────────
function Connect-Services {
    Write-SectionHeader "Authentication"

    # Prompt for TenantId if not supplied
    if ([string]::IsNullOrWhiteSpace($Script:TenantId)) {
        Write-Host "  [?] Enter Tenant ID or domain (e.g. contoso.onmicrosoft.com): " -ForegroundColor Yellow -NoNewline
        $Script:TenantId = Read-Host
        if ([string]::IsNullOrWhiteSpace($Script:TenantId)) {
            Write-Err "TenantId cannot be empty. Aborting."
            exit 1
        }
    }

    Write-Dbg "TenantId supplied: '$($Script:TenantId)'" -Level "INFO"

    # ── Microsoft Graph ──────────────────────────────────────────────────────
    Write-Info "Connecting to Microsoft Graph (Device Auth)..."
    try {
        $scopes = "User.Read.All","Directory.Read.All","Policy.Read.All",
                  "IdentityRiskyUser.Read.All","SecurityEvents.Read.All",
                  "AuditLog.Read.All","Reports.Read.All","Organization.Read.All",
                  "Application.Read.All","RoleManagement.Read.Directory",
                  "UserAuthenticationMethod.Read.All","TeamSettings.Read.All","Sites.Read.All"

        Write-Dbg "Requesting scopes: $($scopes -join ', ')" -Level "API"
        Connect-MgGraph -Scopes $scopes -TenantId $Script:TenantId -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
        Write-Dbg "Connect-MgGraph call returned without error" -Level "OK"

        $ctx = Get-MgContext
        Write-Dbg "Get-MgContext → TenantId='$($ctx.TenantId)'  Account='$($ctx.Account)'  Scopes=$($ctx.Scopes.Count)" -Level "API"

        if ($null -eq $ctx -or [string]::IsNullOrEmpty($ctx.TenantId)) {
            throw "Get-MgContext returned null — connection may have failed silently."
        }

        # Check which scopes were actually granted
        if ($DebugMode) {
            Write-DebugSection "Granted Scopes"
            $ctx.Scopes | Sort-Object | ForEach-Object { Write-Dbg "  SCOPE: $_" -Level "OK" }
            $requested = $scopes
            $missing = $requested | Where-Object { $_ -notin $ctx.Scopes }
            if ($missing) {
                foreach ($s in $missing) { Write-Dbg "  MISSING SCOPE: $s  ← stats/checks using this scope will return 0" -Level "WARN" }
            } else {
                Write-Dbg "All requested scopes were granted." -Level "OK"
            }
        }

        $Script:TenantId = $ctx.TenantId
        $Script:GraphConnected = $true

        # Get display name
        try {
            $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
            $Script:TenantDisplayName = $org.DisplayName
            Write-Dbg "Organization display name: '$($Script:TenantDisplayName)'" -Level "OK"
        } catch {
            $Script:TenantDisplayName = $ctx.TenantId
            Write-Dbg "Get-MgOrganization failed — using TenantId as display name. Error: $_" -Level "WARN"
        }
        Write-Success "Connected to Graph. Tenant: '$($Script:TenantDisplayName)' ($($Script:TenantId))"
    } catch {
        Write-Err "Microsoft Graph connection failed: $_"
        Write-Err "Graph-dependent checks will be skipped."
        Write-Dbg "GRAPH CONNECTION FAILURE — all Graph-based stats will remain 0. Exception: $_" -Level "ERROR"
        $Script:GraphConnected = $false
    }

    # ── Exchange Online ──────────────────────────────────────────────────────
    Write-Info "Connecting to Exchange Online (Device Auth)..."
    try {
        Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
        $Script:ExoConnected = $true
        Write-Success "Connected to Exchange Online."
        Write-Dbg "ExchangeOnline connected successfully" -Level "OK"
    } catch {
        Write-Err "Exchange Online connection failed: $_"
        Write-Err "Email-dependent checks will be skipped."
        Write-Dbg "EXO CONNECTION FAILURE — EML/DLP stats will remain 0. Exception: $_" -Level "ERROR"
        $Script:ExoConnected = $false
    }

    Write-Dbg "Connection state → GraphConnected=$($Script:GraphConnected)  ExoConnected=$($Script:ExoConnected)" -Level "INFO"
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 1  —  IDENTITY & MFA
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-IdentityChecks {
    if ($SkipIdentity) { Write-Skip "Identity & MFA checks skipped (–SkipIdentity)."; return }
    if (-not $Script:GraphConnected) {
        Write-Skip "Graph not connected — skipping Identity checks."
        Write-Dbg "SKIPPED all Identity checks → GraphConnected=false. Stats TotalUsers/EnabledUsers/GuestUsers/GlobalAdmins/StaleUsers/MFAPct/AdminNoMFA/EnabledCAPolicies remain 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 1 — Identity & MFA"
    Write-Info "Analyzing Identity & MFA..."
    Write-DebugSection "Identity & MFA — API Calls"

    # ── Fetch users ──────────────────────────────────────────────────────────
    $allUsers    = @()
    $enabledUsers = @()
    $guestUsers  = @()
    try {
        Write-Dbg "API: Get-MgUser -All (requesting Id,DisplayName,UPN,AccountEnabled,UserType,SignInActivity,CreatedDateTime)" -Level "API"
        $allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,SignInActivity,CreatedDateTime" -ErrorAction Stop
        $enabledUsers = $allUsers | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq "Member" }
        $guestUsers   = $allUsers | Where-Object { $_.UserType -eq "Guest" }
        Set-Stat "TotalUsers"   $allUsers.Count
        Set-Stat "EnabledUsers" $enabledUsers.Count
        Set-Stat "GuestUsers"   $guestUsers.Count
        Write-Dbg "Users fetched: Total=$($allUsers.Count)  Enabled/Members=$($enabledUsers.Count)  Guests=$($guestUsers.Count)" -Level "OK"
        if ($allUsers.Count -eq 0) {
            Write-Dbg "WARNING: Get-MgUser returned 0 users. Possible causes: insufficient scope (User.Read.All), wrong tenant, or tenant has no users." -Level "WARN"
        }
    } catch {
        Write-Err "Failed to retrieve users: $_"
        Write-Dbg "EXCEPTION in Get-MgUser: $_  → TotalUsers/EnabledUsers/GuestUsers stay 0" -Level "ERROR"
    }

    # ── IDN-001  Stale accounts ──────────────────────────────────────────────
    try {
        $cutoff = (Get-Date).AddDays(-90)
        Write-Dbg "IDN-001: Checking stale accounts (no sign-in since $($cutoff.ToString('yyyy-MM-dd')))" -Level "API"
        $stale = $enabledUsers | Where-Object {
            $_.SignInActivity -and
            $_.SignInActivity.LastSignInDateTime -and
            [datetime]$_.SignInActivity.LastSignInDateTime -lt $cutoff
        }
        Set-Stat "StaleUsers" $stale.Count
        Write-Dbg "IDN-001: stale=$($stale.Count)  (users with SignInActivity populated: $(($enabledUsers | Where-Object {$_.SignInActivity -and $_.SignInActivity.LastSignInDateTime}).Count))" -Level "OK"
        if ($stale.Count -eq 0) {
            Add-Finding -CheckId "IDN-001" -Domain "Identity & MFA" -Title "Stale User Accounts" `
                -Status "Pass" -CurrentValue "0 stale accounts" -ExpectedValue "0 stale accounts" `
                -Severity "Medium" -Description "No enabled user accounts have been inactive for 90+ days." `
                -Recommendation "Continue reviewing accounts quarterly." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins"
        } else {
            Add-Finding -CheckId "IDN-001" -Domain "Identity & MFA" -Title "Stale User Accounts" `
                -Status "Fail" -CurrentValue "$($stale.Count) stale accounts" -ExpectedValue "0 stale accounts" `
                -Severity "Medium" -Description "$($stale.Count) enabled accounts have had no sign-in activity in the last 90 days, increasing the attack surface." `
                -Recommendation "Review and disable or delete accounts with no recent sign-in activity. Use Entra ID Access Reviews for automation." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview"
        }
    } catch { Write-Err "IDN-001 failed: $_"; Write-Dbg "IDN-001 EXCEPTION: $_  → StaleUsers stays 0" -Level "ERROR" }

    # ── IDN-002  Guest user count ────────────────────────────────────────────
    try {
        $gCount = $guestUsers.Count
        $status = if ($gCount -le 20) { "Pass" } else { "Warning" }
        Add-Finding -CheckId "IDN-002" -Domain "Identity & MFA" -Title "Guest User Count" `
            -Status $status -CurrentValue "$gCount guest users" -ExpectedValue "≤20 guest users" `
            -Severity "Medium" -Description "There are $gCount guest users in the tenant. Excessive guests increase risk of data exfiltration." `
            -Recommendation "Review guest access regularly. Implement Entra ID Access Reviews for guests. Restrict guest invitations to admins only." `
            -Reference "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b"
    } catch { Write-Err "IDN-002 failed: $_"; Write-Dbg "IDN-002 EXCEPTION: $_" -Level "ERROR" }

    # ── IDN-003  Global Administrator count ──────────────────────────────────
    try {
        Write-Dbg "IDN-003: Get-MgDirectoryRole filtering for 'Global Administrator'" -Level "API"
        $gaRoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop).Id
        $globalAdmins = @()
        if ($gaRoleId) {
            Write-Dbg "IDN-003: Role ID found: $gaRoleId — fetching members" -Level "OK"
            $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRoleId -ErrorAction Stop
        } else {
            Write-Dbg "IDN-003: Global Administrator role not found in directory (role may not be activated yet)" -Level "WARN"
        }
        $gaCount = $globalAdmins.Count
        Set-Stat "GlobalAdmins" $gaCount
        Write-Dbg "IDN-003: GlobalAdmins=$gaCount" -Level "OK"
        if ($gaCount -ge 2 -and $gaCount -le 4) {
            Add-Finding -CheckId "IDN-003" -Domain "Identity & MFA" -Title "Global Administrator Count" `
                -Status "Pass" -CurrentValue "$gaCount Global Admins" -ExpectedValue "2–4 admins" `
                -Severity "High" -Description "The tenant has $gaCount Global Administrators, which is within the recommended range." `
                -Recommendation "Maintain 2-4 Global Admins. Prefer role-specific admin roles where possible." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices"
        } elseif ($gaCount -lt 2) {
            Add-Finding -CheckId "IDN-003" -Domain "Identity & MFA" -Title "Global Administrator Count" `
                -Status "Warning" -CurrentValue "$gaCount Global Admins" -ExpectedValue "2–4 admins" `
                -Severity "Low" -Description "Only $gaCount Global Administrator(s) found. Having fewer than 2 is a risk for tenant lockout." `
                -Recommendation "Add a second break-glass Global Admin account. Store credentials securely offline." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access"
        } else {
            Add-Finding -CheckId "IDN-003" -Domain "Identity & MFA" -Title "Global Administrator Count" `
                -Status "Fail" -CurrentValue "$gaCount Global Admins" -ExpectedValue "2–4 admins" `
                -Severity "High" -Description "$gaCount Global Administrators exist. Excessive admins dramatically increase the blast radius of a compromise." `
                -Recommendation "Reduce Global Admins to 2-4. Assign least-privilege roles (e.g., Exchange Admin, User Admin) for day-to-day tasks." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices"
        }
    } catch { Write-Err "IDN-003 failed: $_"; Write-Dbg "IDN-003 EXCEPTION: $_  → GlobalAdmins stays 0" -Level "ERROR" }

    # ── IDN-004  Conditional Access policies ─────────────────────────────────
    try {
        Write-Dbg "IDN-004: Get-MgIdentityConditionalAccessPolicy" -Level "API"
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        $enabledCA  = $caPolicies | Where-Object { $_.State -eq "enabled" }
        Set-Stat "EnabledCAPolicies" $enabledCA.Count
        Write-Dbg "IDN-004: Total CA policies=$($caPolicies.Count)  Enabled=$($enabledCA.Count)  ReportOnly=$(($caPolicies | Where-Object {$_.State -eq 'enabledForReportingButNotEnforced'}).Count)  Disabled=$(($caPolicies | Where-Object {$_.State -eq 'disabled'}).Count)" -Level "OK"
        if ($enabledCA.Count -ge 5) {
            Add-Finding -CheckId "IDN-004" -Domain "Identity & MFA" -Title "Conditional Access Policies" `
                -Status "Pass" -CurrentValue "$($enabledCA.Count) enabled CA policies" -ExpectedValue "≥5 enabled policies" `
                -Severity "Critical" -Description "$($enabledCA.Count) Conditional Access policies are enabled, providing strong access control." `
                -Recommendation "Regularly review and audit CA policies. Ensure MFA, device compliance, and location controls are in place." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview"
        } elseif ($enabledCA.Count -eq 0) {
            Add-Finding -CheckId "IDN-004" -Domain "Identity & MFA" -Title "Conditional Access Policies" `
                -Status "Fail" -CurrentValue "0 enabled CA policies" -ExpectedValue "≥5 enabled policies" `
                -Severity "Critical" -Description "No Conditional Access policies are enabled. This means no granular access controls are in place for any sign-in scenarios." `
                -Recommendation "Immediately create CA policies. Start with: require MFA for all users, block legacy auth, require compliant devices, and block sign-ins from risky locations." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/plan-conditional-access"
        } else {
            Add-Finding -CheckId "IDN-004" -Domain "Identity & MFA" -Title "Conditional Access Policies" `
                -Status "Fail" -CurrentValue "$($enabledCA.Count) enabled CA policies" -ExpectedValue "≥5 enabled policies" `
                -Severity "High" -Description "Only $($enabledCA.Count) Conditional Access policy/policies enabled. Insufficient coverage for a comprehensive security posture." `
                -Recommendation "Expand CA policies to cover: MFA for admins, MFA for all users, block legacy authentication, require compliant devices, sign-in risk policies." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common"
        }
    } catch { Write-Err "IDN-004 failed: $_"; Write-Dbg "IDN-004 EXCEPTION: $_  → EnabledCAPolicies stays 0" -Level "ERROR" }

    # ── IDN-005  Legacy authentication blocked ────────────────────────────────
    try {
        $caPolicies2 = if ($null -ne (Get-Variable 'caPolicies' -ErrorAction SilentlyContinue)) { $caPolicies } else {
            Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        }
        $legacyBlockPolicy = $caPolicies2 | Where-Object {
            $_.State -eq "enabled" -and
            $_.Conditions.ClientAppTypes -and
            ($_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
             $_.Conditions.ClientAppTypes -contains "other") -and
            $_.GrantControls.BuiltInControls -contains "block"
        }
        if ($legacyBlockPolicy) {
            Add-Finding -CheckId "IDN-005" -Domain "Identity & MFA" -Title "Legacy Authentication Blocked" `
                -Status "Pass" -CurrentValue "Legacy auth block policy exists" -ExpectedValue "Block policy exists" `
                -Severity "High" -Description "A Conditional Access policy blocking legacy authentication protocols is enabled." `
                -Recommendation "Verify the policy covers all legacy auth client types and applies to all users." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"
        } else {
            Add-Finding -CheckId "IDN-005" -Domain "Identity & MFA" -Title "Legacy Authentication Blocked" `
                -Status "Fail" -CurrentValue "No legacy auth block policy found" -ExpectedValue "Block policy exists" `
                -Severity "High" -Description "No Conditional Access policy blocking legacy authentication was found. Legacy protocols (IMAP, POP3, SMTP AUTH, etc.) bypass MFA, making them a primary attack vector for password spray attacks." `
                -Recommendation "Create a CA policy targeting 'Exchange ActiveSync clients' and 'Other clients' with a Grant control of 'Block access'. Test in report-only mode first." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"
        }
    } catch { Write-Err "IDN-005 failed: $_"; Write-Dbg "IDN-005 EXCEPTION: $_" -Level "ERROR" }

    # ── IDN-006  MFA Registration Rate ────────────────────────────────────────
    try {
        Write-Dbg "IDN-006: Get-MgReportAuthenticationMethodUserRegistrationDetail -All (requires Reports.Read.All + UserAuthenticationMethod.Read.All)" -Level "API"
        $mfaReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
        $totalReg = $mfaReport.Count
        $mfaReg   = ($mfaReport | Where-Object { $_.IsMfaRegistered -eq $true }).Count
        $mfaPct   = if ($totalReg -gt 0) { [math]::Round($mfaReg / $totalReg * 100, 1) } else { 0 }
        Set-Stat "MFAPct" $mfaPct
        Write-Dbg "IDN-006: MFA report entries=$totalReg  Registered=$mfaReg  Rate=$mfaPct%" -Level "OK"
        if ($totalReg -eq 0) {
            Write-Dbg "IDN-006: MFA report returned 0 entries — possible cause: missing UserAuthenticationMethod.Read.All scope or P1/P2 license required." -Level "WARN"
        }
        if ($mfaPct -ge 90) {
            Add-Finding -CheckId "IDN-006" -Domain "Identity & MFA" -Title "MFA Registration Rate" `
                -Status "Pass" -CurrentValue "$mfaPct% users MFA registered" -ExpectedValue "≥90%" `
                -Severity "Critical" -Description "$mfaReg of $totalReg users ($mfaPct%) have registered for MFA." `
                -Recommendation "Maintain high MFA adoption. Consider enforcing passwordless or phishing-resistant MFA." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks"
        } elseif ($mfaPct -lt 50) {
            Add-Finding -CheckId "IDN-006" -Domain "Identity & MFA" -Title "MFA Registration Rate" `
                -Status "Fail" -CurrentValue "$mfaPct% users MFA registered" -ExpectedValue "≥90%" `
                -Severity "Critical" -Description "Only $mfaReg of $totalReg users ($mfaPct%) have registered for MFA. This is critically low." `
                -Recommendation "Deploy a CA policy requiring MFA registration (Entra ID MFA Registration policy). Communicate urgency to users and set a hard deadline." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-mfa-policy"
        } else {
            Add-Finding -CheckId "IDN-006" -Domain "Identity & MFA" -Title "MFA Registration Rate" `
                -Status "Fail" -CurrentValue "$mfaPct% users MFA registered" -ExpectedValue "≥90%" `
                -Severity "High" -Description "$mfaReg of $totalReg users ($mfaPct%) have registered for MFA. $($totalReg - $mfaReg) users remain unprotected." `
                -Recommendation "Create an MFA registration campaign. Use Entra ID's MFA registration policy to enforce registration for unregistered users." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-mfa-policy"
        }
    } catch { Write-Err "IDN-006 failed (may require P2 license): $_"; Write-Dbg "IDN-006 EXCEPTION: $_  → MFAPct stays 0" -Level "ERROR" }

    # ── IDN-007  Admins without MFA ───────────────────────────────────────────
    try {
        Write-Dbg "IDN-007: Checking MFA status for privileged role members" -Level "API"
        $adminRoleNames = @("Global Administrator","Exchange Administrator","SharePoint Administrator",
                            "User Administrator","Security Administrator","Conditional Access Administrator",
                            "Privileged Role Administrator","Billing Administrator","Teams Administrator")
        $adminUserIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($roleName in $adminRoleNames) {
            try {
                $role = Get-MgDirectoryRole -Filter "DisplayName eq '$roleName'" -ErrorAction SilentlyContinue
                if ($role) {
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                    $members | ForEach-Object { $null = $adminUserIds.Add($_.Id) }
                    Write-Dbg "  IDN-007: Role '$roleName' → $(@($members).Count) member(s)" -Level "INFO"
                } else {
                    Write-Dbg "  IDN-007: Role '$roleName' not activated in this tenant" -Level "INFO"
                }
            } catch {
                Write-Dbg "  IDN-007: Failed to get members for '$roleName': $_" -Level "WARN"
            }
        }
        Write-Dbg "IDN-007: Unique admin user IDs collected: $($adminUserIds.Count)" -Level "OK"
        $adminsWithoutMFA = 0
        foreach ($adminId in $adminUserIds) {
            try {
                $regDetail = Get-MgReportAuthenticationMethodUserRegistrationDetail -UserRegistrationDetailsId $adminId -ErrorAction SilentlyContinue
                if ($regDetail -and $regDetail.IsMfaRegistered -eq $false) {
                    $adminsWithoutMFA++
                    Write-Dbg "  IDN-007: Admin ID $adminId has NO MFA registered" -Level "WARN"
                }
            } catch {
                Write-Dbg "  IDN-007: Could not get MFA detail for admin ID $adminId — $_" -Level "WARN"
            }
        }
        Set-Stat "AdminNoMFA" $adminsWithoutMFA
        Write-Dbg "IDN-007: AdminNoMFA=$adminsWithoutMFA out of $($adminUserIds.Count) unique admins checked" -Level "OK"
        if ($adminsWithoutMFA -eq 0) {
            Add-Finding -CheckId "IDN-007" -Domain "Identity & MFA" -Title "Administrators Without MFA" `
                -Status "Pass" -CurrentValue "All admins have MFA registered" -ExpectedValue "0 admins without MFA" `
                -Severity "Critical" -Description "All privileged administrators have MFA registered." `
                -Recommendation "Consider requiring phishing-resistant MFA (FIDO2/Windows Hello) for Global Admins." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods"
        } else {
            Add-Finding -CheckId "IDN-007" -Domain "Identity & MFA" -Title "Administrators Without MFA" `
                -Status "Fail" -CurrentValue "$adminsWithoutMFA admin(s) without MFA" -ExpectedValue "0 admins without MFA" `
                -Severity "Critical" -Description "$adminsWithoutMFA privileged administrator(s) do not have MFA registered. Admin accounts without MFA are the most targeted accounts in credential attacks." `
                -Recommendation "Immediately enforce MFA for all admin accounts via Conditional Access. Do not allow any exceptions for administrative roles." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa"
        }
    } catch { Write-Err "IDN-007 failed: $_"; Write-Dbg "IDN-007 EXCEPTION: $_  → AdminNoMFA stays 0" -Level "ERROR" }

    # ── IDN-008  Risky Users ──────────────────────────────────────────────────
    try {
        Write-Dbg "IDN-008: Get-MgRiskyUser (requires IdentityRiskyUser.Read.All + Entra ID P2)" -Level "API"
        $riskyUsers = Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -ErrorAction Stop
        $riskyCount = @($riskyUsers).Count
        Write-Dbg "IDN-008: At-risk users=$riskyCount" -Level "OK"
        if ($riskyCount -eq 0) {
            Add-Finding -CheckId "IDN-008" -Domain "Identity & MFA" -Title "Risky Users (Identity Protection)" `
                -Status "Pass" -CurrentValue "0 at-risk users" -ExpectedValue "0 at-risk users" `
                -Severity "High" -Description "No users are currently flagged as at-risk by Microsoft Entra Identity Protection." `
                -Recommendation "Ensure Identity Protection risk policies are configured to automatically remediate risky users." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection"
        } else {
            Add-Finding -CheckId "IDN-008" -Domain "Identity & MFA" -Title "Risky Users (Identity Protection)" `
                -Status "Fail" -CurrentValue "$riskyCount user(s) at risk" -ExpectedValue "0 at-risk users" `
                -Severity "High" -Description "$riskyCount user(s) are currently flagged as at-risk by Entra Identity Protection. These accounts may be compromised." `
                -Recommendation "Investigate all at-risk users immediately in the Entra ID portal. Force password reset and review recent sign-in activity. Configure automatic remediation policies." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-remediate-unblock"
        }
    } catch { Write-Err "IDN-008 failed (requires P2 license): $_"; Write-Dbg "IDN-008 EXCEPTION: $_" -Level "ERROR" }

    # ── IDN-009  Self-Service Password Reset ──────────────────────────────────
    try {
        Write-Dbg "IDN-009: Get-MgPolicyAuthorizationPolicy" -Level "API"
        $sspr = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $ssrpEnabled = $sspr.AllowedToResetPassword -or
                       ($sspr.DefaultUserRolePermissions -and
                        $sspr.DefaultUserRolePermissions.AllowedToReadOtherUsers)
        # Try directory settings for SSPR
        try {
            $ssSettings = Get-MgBetaDirectorySetting -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "Password Rule Settings" }
            if ($ssSettings) { $ssrpEnabled = $true }
        } catch {}

        Add-Finding -CheckId "IDN-009" -Domain "Identity & MFA" -Title "Self-Service Password Reset (SSPR)" `
            -Status "Info" -CurrentValue "SSPR configuration detected" -ExpectedValue "SSPR enabled for all users" `
            -Severity "Medium" -Description "SSPR configuration was retrieved. Verify SSPR is enabled for all users in the Entra ID portal under Password Reset settings." `
            -Recommendation "Enable SSPR for all users. Require at least 2 authentication methods for reset. Monitor SSPR usage via audit logs." `
            -Reference "https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-howitworks"
    } catch { Write-Err "IDN-009 failed: $_"; Write-Dbg "IDN-009 EXCEPTION: $_" -Level "ERROR" }

    Write-StatsSnapshot
    Write-Success "Identity & MFA analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 2  —  EMAIL SECURITY
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-EmailChecks {
    if ($SkipEmail) { Write-Skip "Email Security checks skipped (–SkipEmail)."; return }
    if (-not $Script:ExoConnected) {
        Write-Skip "Exchange Online not connected — skipping Email Security checks."
        Write-Dbg "SKIPPED all Email checks → ExoConnected=false." -Level "WARN"
        Add-Finding -CheckId "EML-000" -Domain "Email Security" -Title "Exchange Online Not Connected" `
            -Status "Info" -CurrentValue "Not connected" -ExpectedValue "Connected" `
            -Severity "Informational" -Description "Exchange Online connection was not available. Email security checks were skipped." `
            -Recommendation "Re-run the tool with Exchange Online access to assess email security." `
            -Reference "https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell"
        return
    }

    Write-SectionHeader "Domain 2 — Email Security"
    Write-Info "Analyzing Email Security..."
    Write-DebugSection "Email Security — API Calls"

    # ── EML-001  Anti-phishing: Mailbox Intelligence ──────────────────────────
    try {
        Write-Dbg "EML-001: Get-AntiPhishPolicy" -Level "API"
        $antiPhish = Get-AntiPhishPolicy -ErrorAction Stop
        $defaultPolicy = $antiPhish | Where-Object { $_.IsDefault -eq $true }
        $hasMailboxIntel = $antiPhish | Where-Object { $_.EnableMailboxIntelligence -eq $true }
        Write-Dbg "EML-001: $($antiPhish.Count) anti-phish policies  Default=$($defaultPolicy.Name)  MailboxIntelEnabled=$($hasMailboxIntel.Count)" -Level "OK"
        if ($hasMailboxIntel) {
            Add-Finding -CheckId "EML-001" -Domain "Email Security" -Title "Anti-Phishing: Mailbox Intelligence" `
                -Status "Pass" -CurrentValue "Mailbox Intelligence enabled" -ExpectedValue "Enabled" `
                -Severity "High" -Description "Mailbox Intelligence is enabled in at least one anti-phishing policy." `
                -Recommendation "Ensure mailbox intelligence is enabled in all anti-phishing policies and consider enabling impersonation protection." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about"
        } else {
            Add-Finding -CheckId "EML-001" -Domain "Email Security" -Title "Anti-Phishing: Mailbox Intelligence" `
                -Status "Fail" -CurrentValue "Mailbox Intelligence disabled" -ExpectedValue "Enabled" `
                -Severity "High" -Description "Mailbox Intelligence is not enabled. This feature uses AI to detect unusual email patterns and protect against impersonation attacks." `
                -Recommendation "Edit the default anti-phishing policy and enable 'Mailbox intelligence' and 'Mailbox intelligence for impersonation protection'." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about"
        }
    } catch { Write-Err "EML-001 failed: $_"; Write-Dbg "EML-001 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-002  Spoof Intelligence ───────────────────────────────────────────
    try {
        Write-Dbg "EML-002: Get-AntiPhishPolicy (checking EnableSpoofIntelligence)" -Level "API"
        $antiPhishP = Get-AntiPhishPolicy -ErrorAction Stop
        $spoofEnabled = $antiPhishP | Where-Object { $_.EnableSpoofIntelligence -eq $true }
        Write-Dbg "EML-002: SpoofIntelligenceEnabled policies=$($spoofEnabled.Count)" -Level "OK"
        if ($spoofEnabled) {
            Add-Finding -CheckId "EML-002" -Domain "Email Security" -Title "Anti-Phishing: Spoof Intelligence" `
                -Status "Pass" -CurrentValue "Spoof Intelligence enabled" -ExpectedValue "Enabled" `
                -Severity "High" -Description "Spoof Intelligence is enabled to detect spoofed senders." `
                -Recommendation "Regularly review the spoof intelligence report for blocked/allowed senders." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-spoof-intelligence"
        } else {
            Add-Finding -CheckId "EML-002" -Domain "Email Security" -Title "Anti-Phishing: Spoof Intelligence" `
                -Status "Fail" -CurrentValue "Spoof Intelligence disabled" -ExpectedValue "Enabled" `
                -Severity "High" -Description "Spoof Intelligence is not enabled. This allows spoofed emails to reach users' inboxes." `
                -Recommendation "Enable Spoof Intelligence in the anti-phishing policy and configure the action for detected spoofed messages." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-spoof-intelligence"
        }
    } catch { Write-Err "EML-002 failed: $_"; Write-Dbg "EML-002 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-003  DKIM ─────────────────────────────────────────────────────────
    try {
        Write-Dbg "EML-003: Get-AcceptedDomain + Get-DkimSigningConfig per domain" -Level "API"
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_.DomainType -eq "Authoritative" }
        Write-Dbg "EML-003: Authoritative domains found: $(($acceptedDomains | ForEach-Object {$_.DomainName}) -join ', ')" -Level "OK"
        $unsignedDomains  = @()
        foreach ($dom in $acceptedDomains) {
            try {
                $dkim = Get-DkimSigningConfig -Identity $dom.DomainName -ErrorAction SilentlyContinue
                if (-not $dkim -or $dkim.Enabled -eq $false) {
                    $unsignedDomains += $dom.DomainName
                    Write-Dbg "  EML-003: $($dom.DomainName) → DKIM DISABLED or not configured" -Level "WARN"
                } else {
                    Write-Dbg "  EML-003: $($dom.DomainName) → DKIM enabled ✓" -Level "OK"
                }
            } catch {
                $unsignedDomains += $dom.DomainName
                Write-Dbg "  EML-003: $($dom.DomainName) → DKIM check failed: $_" -Level "WARN"
            }
        }
        if ($unsignedDomains.Count -eq 0) {
            Add-Finding -CheckId "EML-003" -Domain "Email Security" -Title "DKIM Signing" `
                -Status "Pass" -CurrentValue "All domains DKIM-signed" -ExpectedValue "All domains signed" `
                -Severity "High" -Description "DKIM signing is enabled for all accepted domains." `
                -Recommendation "Rotate DKIM keys periodically (every 6-12 months) for security hygiene." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure"
        } else {
            Add-Finding -CheckId "EML-003" -Domain "Email Security" -Title "DKIM Signing" `
                -Status "Fail" -CurrentValue "$($unsignedDomains.Count) unsigned domain(s): $($unsignedDomains -join ', ')" -ExpectedValue "All domains signed" `
                -Severity "High" -Description "$($unsignedDomains.Count) domain(s) do not have DKIM signing enabled. Without DKIM, outbound mail cannot be cryptographically verified, enabling spoofing." `
                -Recommendation "Enable DKIM for all custom domains in the Security & Compliance center or via PowerShell: Enable-DkimSigningConfig -Identity <domain>. Also ensure DMARC is configured." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure"
        }
    } catch { Write-Err "EML-003 failed: $_"; Write-Dbg "EML-003 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-004  Safe Attachments ─────────────────────────────────────────────
    try {
        Write-Dbg "EML-004: Get-SafeAttachmentPolicy (requires Defender for Office 365 Plan 1/2)" -Level "API"
        $safeAtt = Get-SafeAttachmentPolicy -ErrorAction Stop
        Write-Dbg "EML-004: SafeAttachmentPolicies=$($safeAtt.Count)" -Level "OK"
        if ($safeAtt -and $safeAtt.Count -gt 0) {
            Add-Finding -CheckId "EML-004" -Domain "Email Security" -Title "Safe Attachments Policy" `
                -Status "Pass" -CurrentValue "$($safeAtt.Count) policy/policies" -ExpectedValue "Policy exists" `
                -Severity "High" -Description "Safe Attachments policy is configured, providing sandbox-based attachment scanning." `
                -Recommendation "Ensure Safe Attachments is set to 'Block' or 'Replace' mode (not Monitor). Enable for SharePoint, OneDrive, and Teams." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about"
        } else {
            Add-Finding -CheckId "EML-004" -Domain "Email Security" -Title "Safe Attachments Policy" `
                -Status "Fail" -CurrentValue "No Safe Attachments policy" -ExpectedValue "Policy exists" `
                -Severity "High" -Description "No Safe Attachments policy is configured. This requires Microsoft Defender for Office 365 (Plan 1 or 2). Without it, malicious attachments can reach users." `
                -Recommendation "Configure Safe Attachments in Microsoft Defender for Office 365. Enable for email, SharePoint, OneDrive, and Teams. Set action to 'Block'." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-policies-configure"
        }
    } catch { Write-Err "EML-004 failed: $_"; Write-Dbg "EML-004 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-005  Safe Links ───────────────────────────────────────────────────
    try {
        Write-Dbg "EML-005: Get-SafeLinksPolicy (requires Defender for Office 365 Plan 1/2)" -Level "API"
        $safeLinks = Get-SafeLinksPolicy -ErrorAction Stop
        Write-Dbg "EML-005: SafeLinksPolicies=$($safeLinks.Count)" -Level "OK"
        if ($safeLinks -and $safeLinks.Count -gt 0) {
            Add-Finding -CheckId "EML-005" -Domain "Email Security" -Title "Safe Links Policy" `
                -Status "Pass" -CurrentValue "$($safeLinks.Count) policy/policies" -ExpectedValue "Policy exists" `
                -Severity "High" -Description "Safe Links policy is configured, providing URL scanning and time-of-click protection." `
                -Recommendation "Enable 'Track user clicks', 'Do not allow users to click through to original URL', and safe links for Teams/Office apps." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about"
        } else {
            Add-Finding -CheckId "EML-005" -Domain "Email Security" -Title "Safe Links Policy" `
                -Status "Fail" -CurrentValue "No Safe Links policy" -ExpectedValue "Policy exists" `
                -Severity "High" -Description "No Safe Links policy is configured. Without Safe Links, malicious URLs in email are not scanned, leaving users vulnerable to phishing via links." `
                -Recommendation "Configure Safe Links in Microsoft Defender for Office 365. Enable URL rewriting, tracking, and block when URL is malicious." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-policies-configure"
        }
    } catch { Write-Err "EML-005 failed: $_"; Write-Dbg "EML-005 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-006  Outbound Spam Policy ─────────────────────────────────────────
    try {
        Write-Dbg "EML-006: Get-HostedOutboundSpamFilterPolicy" -Level "API"
        $outboundSpam = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        Write-Dbg "EML-006: OutboundSpamPolicies=$($outboundSpam.Count)" -Level "OK"
        if ($outboundSpam) {
            Add-Finding -CheckId "EML-006" -Domain "Email Security" -Title "Outbound Spam Policy" `
                -Status "Pass" -CurrentValue "Outbound spam policy configured" -ExpectedValue "Configured" `
                -Severity "Medium" -Description "An outbound spam filter policy is configured." `
                -Recommendation "Ensure notification is configured to alert admins when a user is blocked for spam. Set RecipientLimitExternalPerHour to a reasonable value." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure"
        } else {
            Add-Finding -CheckId "EML-006" -Domain "Email Security" -Title "Outbound Spam Policy" `
                -Status "Warning" -CurrentValue "No outbound spam policy" -ExpectedValue "Configured" `
                -Severity "Medium" -Description "No outbound spam filter policy found. Without this, compromised accounts can send spam/phishing without detection." `
                -Recommendation "Configure an outbound spam policy and set up admin notifications for accounts that exceed sending limits." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure"
        }
    } catch { Write-Err "EML-006 failed: $_"; Write-Dbg "EML-006 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-007  Audit Logging ────────────────────────────────────────────────
    try {
        Write-Dbg "EML-007: Get-AdminAuditLogConfig" -Level "API"
        $adminAudit = Get-AdminAuditLogConfig -ErrorAction Stop
        Write-Dbg "EML-007: UnifiedAuditLogIngestionEnabled=$($adminAudit.UnifiedAuditLogIngestionEnabled)" -Level "OK"
        if ($adminAudit.UnifiedAuditLogIngestionEnabled) {
            Add-Finding -CheckId "EML-007" -Domain "Email Security" -Title "Unified Audit Log" `
                -Status "Pass" -CurrentValue "Audit logging enabled" -ExpectedValue "Enabled" `
                -Severity "Critical" -Description "Unified audit logging is enabled for this tenant." `
                -Recommendation "Ensure audit log retention is set to at least 90 days (1 year recommended for compliance). Export logs to SIEM." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-solutions-overview"
        } else {
            Add-Finding -CheckId "EML-007" -Domain "Email Security" -Title "Unified Audit Log" `
                -Status "Fail" -CurrentValue "Audit logging DISABLED" -ExpectedValue "Enabled" `
                -Severity "Critical" -Description "Unified audit logging is disabled. Without audit logs, security investigations, compliance reporting, and forensics are impossible." `
                -Recommendation "Enable unified audit logging immediately: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. This is required for compliance with many standards (ISO 27001, SOC2, etc.)." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/turn-audit-log-search-on-or-off"
        }
    } catch { Write-Err "EML-007 failed: $_"; Write-Dbg "EML-007 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-008  Mailbox Auditing ─────────────────────────────────────────────
    try {
        Write-Dbg "EML-008: Get-OrganizationConfig (checking AuditDisabled)" -Level "API"
        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
        Write-Dbg "EML-008: AuditDisabled=$($orgConfig.AuditDisabled)" -Level "OK"
        if ($orgConfig.AuditDisabled -eq $false) {
            Add-Finding -CheckId "EML-008" -Domain "Email Security" -Title "Mailbox Auditing Default" `
                -Status "Pass" -CurrentValue "Mailbox auditing enabled by default" -ExpectedValue "Enabled" `
                -Severity "Medium" -Description "Mailbox auditing is enabled by default for all mailboxes." `
                -Recommendation "Verify audit actions are configured for MailboxOwner, Delegate, and Admin access. Ensure SendAs and Send On Behalf are audited." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing"
        } else {
            Add-Finding -CheckId "EML-008" -Domain "Email Security" -Title "Mailbox Auditing Default" `
                -Status "Fail" -CurrentValue "Mailbox auditing disabled" -ExpectedValue "Enabled" `
                -Severity "Medium" -Description "Mailbox auditing is not enabled by default. Mailbox access and activities are not being recorded." `
                -Recommendation "Enable mailbox auditing: Set-OrganizationConfig -AuditDisabled $false. This enables auditing for all mailboxes." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing"
        }
    } catch { Write-Err "EML-008 failed: $_"; Write-Dbg "EML-008 EXCEPTION: $_" -Level "ERROR" }

    Write-StatsSnapshot
    Write-Success "Email Security analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 3  —  DATA PROTECTION & DLP
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-DLPChecks {
    if ($SkipDLP) { Write-Skip "DLP checks skipped (–SkipDLP)."; return }
    if (-not $Script:GraphConnected) {
        Write-Skip "Graph not connected — skipping DLP checks."
        Write-Dbg "SKIPPED all DLP checks → GraphConnected=false. DLPPolicies stays 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 3 — Data Protection & DLP"
    Write-Info "Analyzing Data Protection & DLP..."
    Write-DebugSection "Data Protection & DLP — API Calls"

    # ── DLP-001  Sensitivity Labels ───────────────────────────────────────────
    try {
        Write-Dbg "DLP-001: Get-MgInformationProtectionSensitivityLabel (requires InformationProtection.Read scope — may fail on non-E5)" -Level "API"
        $labels = Get-MgInformationProtectionSensitivityLabel -ErrorAction Stop
        Write-Dbg "DLP-001: SensitivityLabels=$($labels.Count)" -Level "OK"
        if ($labels -and $labels.Count -gt 0) {
            Add-Finding -CheckId "DLP-001" -Domain "Data Protection" -Title "Sensitivity Labels" `
                -Status "Pass" -CurrentValue "$($labels.Count) sensitivity label(s) configured" -ExpectedValue "Labels exist" `
                -Severity "High" -Description "$($labels.Count) sensitivity label(s) are configured for data classification." `
                -Recommendation "Ensure labels are published to users via label policies. Train users on proper classification. Enable auto-labeling for sensitive data types." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels"
        } else {
            Add-Finding -CheckId "DLP-001" -Domain "Data Protection" -Title "Sensitivity Labels" `
                -Status "Fail" -CurrentValue "No sensitivity labels configured" -ExpectedValue "Labels exist" `
                -Severity "High" -Description "No sensitivity labels are configured. Without labels, sensitive data cannot be classified, protected, or tracked across the organization." `
                -Recommendation "Create a sensitivity label taxonomy (e.g., Public, Internal, Confidential, Highly Confidential). Configure encryption, watermarks, and access restrictions per label." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/get-started-with-sensitivity-labels"
        }
    } catch { Write-Err "DLP-001 failed: $_"; Write-Dbg "DLP-001 EXCEPTION: $_" -Level "ERROR" }

    # ── DLP-002  Customer Lockbox ─────────────────────────────────────────────
    try {
        Write-Dbg "DLP-002: Checking CustomerLockBoxEnabled via Get-OrganizationConfig" -Level "API"
        if ($Script:ExoConnected) {
            $orgCfg = Get-OrganizationConfig -ErrorAction Stop
            if ($orgCfg.CustomerLockBoxEnabled) {
                Add-Finding -CheckId "DLP-002" -Domain "Data Protection" -Title "Customer Lockbox" `
                    -Status "Pass" -CurrentValue "Customer Lockbox enabled" -ExpectedValue "Enabled" `
                    -Severity "Medium" -Description "Customer Lockbox is enabled. Microsoft engineers must get explicit approval before accessing tenant data." `
                    -Recommendation "Assign Customer Lockbox approvers. Review and respond to lockbox requests promptly." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/customer-lockbox-requests"
            } else {
                Add-Finding -CheckId "DLP-002" -Domain "Data Protection" -Title "Customer Lockbox" `
                    -Status "Warning" -CurrentValue "Customer Lockbox disabled" -ExpectedValue "Enabled" `
                    -Severity "Medium" -Description "Customer Lockbox is not enabled. Microsoft support engineers can access tenant data without explicit customer approval (though still with internal controls)." `
                    -Recommendation "Enable Customer Lockbox in the Microsoft 365 admin center: Settings > Org Settings > Security & Privacy > Customer Lockbox. Requires E5 or add-on." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/customer-lockbox-requests"
            }
        } else {
            Add-Finding -CheckId "DLP-002" -Domain "Data Protection" -Title "Customer Lockbox" `
                -Status "Info" -CurrentValue "EXO not connected" -ExpectedValue "Enabled" `
                -Severity "Medium" -Description "Unable to check Customer Lockbox — Exchange Online connection required." `
                -Recommendation "Reconnect to Exchange Online and re-run the assessment." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/customer-lockbox-requests"
        }
    } catch { Write-Err "DLP-002 failed: $_"; Write-Dbg "DLP-002 EXCEPTION: $_" -Level "ERROR" }

    # ── DLP-003 & DLP-004  DLP Policies ──────────────────────────────────────
    try {
        if ($Script:ExoConnected) {
            Write-Dbg "DLP-003/004: Get-DlpCompliancePolicy" -Level "API"
            $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
            Set-Stat "DLPPolicies" @($dlpPolicies).Count
            Write-Dbg "DLP-003: Total DLP policies=$(@($dlpPolicies).Count)  Modes: $($dlpPolicies | Group-Object Mode | ForEach-Object {"$($_.Name)=$($_.Count)"} | Join-String -Separator ', ')" -Level "OK"
            $enforcedPolicies = @($dlpPolicies | Where-Object { $_.Mode -eq "Enable" })

            if ($dlpPolicies -and $dlpPolicies.Count -gt 0) {
                Add-Finding -CheckId "DLP-003" -Domain "Data Protection" -Title "DLP Policies Exist" `
                    -Status "Pass" -CurrentValue "$($dlpPolicies.Count) DLP policy/policies" -ExpectedValue "At least 1 policy" `
                    -Severity "High" -Description "$($dlpPolicies.Count) DLP policy/policies are configured." `
                    -Recommendation "Ensure DLP policies cover all workloads (Exchange, SharePoint, OneDrive, Teams). Review policy matches regularly." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp"
            } else {
                Add-Finding -CheckId "DLP-003" -Domain "Data Protection" -Title "DLP Policies Exist" `
                    -Status "Fail" -CurrentValue "No DLP policies" -ExpectedValue "At least 1 policy" `
                    -Severity "High" -Description "No Data Loss Prevention (DLP) policies are configured. Sensitive data (PII, financial, health) can leave the organization undetected." `
                    -Recommendation "Create DLP policies to protect sensitive information types (SSN, credit cards, health records). Start with Microsoft's built-in templates." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-create-deploy-policy"
            }

            if ($enforcedPolicies.Count -gt 0) {
                Add-Finding -CheckId "DLP-004" -Domain "Data Protection" -Title "DLP Policies in Enforce Mode" `
                    -Status "Pass" -CurrentValue "$($enforcedPolicies.Count) enforced policy/policies" -ExpectedValue "At least 1 enforced" `
                    -Severity "High" -Description "$($enforcedPolicies.Count) DLP policy/policies are in Enforce (Enable) mode." `
                    -Recommendation "Review policy matches and false positive rates. Adjust rules as needed. Ensure coverage for all sensitive data types." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-policy-design"
            } elseif ($dlpPolicies -and $dlpPolicies.Count -gt 0) {
                Add-Finding -CheckId "DLP-004" -Domain "Data Protection" -Title "DLP Policies in Enforce Mode" `
                    -Status "Fail" -CurrentValue "All policies in audit/test mode" -ExpectedValue "At least 1 enforced" `
                    -Severity "High" -Description "DLP policies exist but all are in Audit or Test mode. No actual data loss prevention is occurring — policies only report, not block." `
                    -Recommendation "After reviewing audit results, switch at least key policies to Enforce mode. Start with the most critical sensitive data types." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-policy-design"
            } else {
                Add-Finding -CheckId "DLP-004" -Domain "Data Protection" -Title "DLP Policies in Enforce Mode" `
                    -Status "Fail" -CurrentValue "No DLP policies at all" -ExpectedValue "At least 1 enforced" `
                    -Severity "High" -Description "No DLP policies exist, therefore none are in enforce mode." `
                    -Recommendation "Create and enforce DLP policies. See DLP-003 recommendation." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-policy-design"
            }
        } else {
            Add-Finding -CheckId "DLP-003" -Domain "Data Protection" -Title "DLP Policies" `
                -Status "Info" -CurrentValue "EXO not connected" -ExpectedValue "Policies exist" `
                -Severity "High" -Description "Unable to check DLP policies — Exchange Online connection required." `
                -Recommendation "Reconnect to Exchange Online and re-run the assessment." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp"
        }
    } catch { Write-Err "DLP-003/004 failed: $_"; Write-Dbg "DLP-003/004 EXCEPTION: $_  → DLPPolicies stays 0" -Level "ERROR" }

    # ── DLP-005  Retention Policies ───────────────────────────────────────────
    try {
        if ($Script:ExoConnected) {
            Write-Dbg "DLP-005: Get-RetentionCompliancePolicy" -Level "API"
            $retPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop
            Write-Dbg "DLP-005: RetentionPolicies=$($retPolicies.Count)" -Level "OK"
            if ($retPolicies -and $retPolicies.Count -gt 0) {
                Add-Finding -CheckId "DLP-005" -Domain "Data Protection" -Title "Retention Policies" `
                    -Status "Pass" -CurrentValue "$($retPolicies.Count) retention policy/policies" -ExpectedValue "At least 1 policy" `
                    -Severity "Medium" -Description "$($retPolicies.Count) retention policy/policies are configured." `
                    -Recommendation "Verify retention policies cover all required workloads. Ensure minimum retention periods meet regulatory requirements." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/retention"
            } else {
                Add-Finding -CheckId "DLP-005" -Domain "Data Protection" -Title "Retention Policies" `
                    -Status "Fail" -CurrentValue "No retention policies" -ExpectedValue "At least 1 policy" `
                    -Severity "Medium" -Description "No retention policies are configured. Data may be deleted before required by regulations, or kept longer than permitted." `
                    -Recommendation "Configure retention policies for Exchange email, SharePoint, OneDrive, and Teams. Align retention periods with regulatory requirements (GDPR, HIPAA, etc.)." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/create-retention-policies"
            }
        } else {
            Add-Finding -CheckId "DLP-005" -Domain "Data Protection" -Title "Retention Policies" `
                -Status "Info" -CurrentValue "EXO not connected" -ExpectedValue "Policies exist" `
                -Severity "Medium" -Description "Unable to check retention policies — Exchange Online connection required." `
                -Recommendation "Reconnect to Exchange Online and re-run the assessment." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/retention"
        }
    } catch { Write-Err "DLP-005 failed: $_"; Write-Dbg "DLP-005 EXCEPTION: $_" -Level "ERROR" }

    Write-StatsSnapshot
    Write-Success "Data Protection & DLP analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 4  —  TEAMS & SHAREPOINT
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-TeamsSharePointChecks {
    if ($SkipTeams) { Write-Skip "Teams & SharePoint checks skipped (–SkipTeams)."; return }
    if (-not $Script:GraphConnected) {
        Write-Skip "Graph not connected — skipping Teams & SharePoint checks."
        Write-Dbg "SKIPPED all Teams/SharePoint checks → GraphConnected=false." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 4 — Teams & SharePoint"
    Write-Info "Analyzing Teams & SharePoint..."
    Write-DebugSection "Teams & SharePoint — API Calls"

    # ── TSP-001  Teams Provisioned (Info) ─────────────────────────────────────
    try {
        Write-Dbg "TSP-001: Get-MgGroup filtering for Teams resource provisioning" -Level "API"
        $teamsCount = 0
        try {
            $teams = Get-MgGroup -Filter "resourceProvisioningOptions/Any(x:x eq 'Team')" -CountVariable teamCount -ConsistencyLevel eventual -ErrorAction Stop
            $teamsCount = @($teams).Count
            Write-Dbg "TSP-001: Teams groups found=$teamsCount" -Level "OK"
        } catch {
            Write-Dbg "TSP-001: Teams query failed (may need ConsistencyLevel=eventual header): $_" -Level "WARN"
        }
        Add-Finding -CheckId "TSP-001" -Domain "Teams & SharePoint" -Title "Microsoft Teams Usage" `
            -Status "Info" -CurrentValue "$teamsCount Teams provisioned" -ExpectedValue "N/A" `
            -Severity "Informational" -Description "$teamsCount Microsoft Teams have been provisioned in this tenant." `
            -Recommendation "Review Teams governance settings. Implement a Teams naming policy, expiration policy, and guest access controls." `
            -Reference "https://learn.microsoft.com/en-us/microsoftteams/teams-overview"
    } catch { Write-Err "TSP-001 failed: $_"; Write-Dbg "TSP-001 EXCEPTION: $_" -Level "ERROR" }

    # ── TSP-002  Guest Invitation Settings ────────────────────────────────────
    try {
        Write-Dbg "TSP-002: Get-MgPolicyAuthorizationPolicy (AllowInvitesFrom)" -Level "API"
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $guestInvite = $authPolicy.AllowInvitesFrom
        Write-Dbg "TSP-002: AllowInvitesFrom='$guestInvite'" -Level "OK"
        if ($guestInvite -eq "adminsAndGuestInviters" -or $guestInvite -eq "adminsGuestInvitersAndAllMembers" -or $null -eq $guestInvite) {
            # Check more specifically
        }
        if ($guestInvite -eq "none" -or $guestInvite -eq "adminsAndGuestInviters") {
            Add-Finding -CheckId "TSP-002" -Domain "Teams & SharePoint" -Title "Guest Invitation Restriction" `
                -Status "Pass" -CurrentValue "Guest invitations restricted to admins/inviters" -ExpectedValue "adminsOnly or restricted" `
                -Severity "High" -Description "Guest invitations are restricted — only admins or designated inviters can send B2B invitations." `
                -Recommendation "Periodically review the Guest Inviter role assignments and audit guest invitation activity." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure"
        } elseif ($guestInvite -eq "everyone") {
            Add-Finding -CheckId "TSP-002" -Domain "Teams & SharePoint" -Title "Guest Invitation Restriction" `
                -Status "Fail" -CurrentValue "All users can invite guests" -ExpectedValue "Restricted to admins" `
                -Severity "High" -Description "All users can invite external guests to the tenant. This can lead to uncontrolled data sharing with external parties." `
                -Recommendation "Restrict guest invitations to admins only: Set AllowInvitesFrom to 'adminsAndGuestInviters' or 'none' in External Collaboration Settings." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure"
        } else {
            Add-Finding -CheckId "TSP-002" -Domain "Teams & SharePoint" -Title "Guest Invitation Restriction" `
                -Status "Warning" -CurrentValue "Guest invitation setting: $guestInvite" -ExpectedValue "adminsOnly" `
                -Severity "High" -Description "Guest invitation setting '$guestInvite' may be overly permissive. Review to ensure only authorized users can invite external guests." `
                -Recommendation "Review and tighten guest invitation settings in Entra External Identities." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure"
        }
    } catch { Write-Err "TSP-002 failed: $_"; Write-Dbg "TSP-002 EXCEPTION: $_" -Level "ERROR" }

    # ── TSP-003  SharePoint Anonymous Sharing ─────────────────────────────────
    try {
        Write-Dbg "TSP-003: Get-MgAdminSharepointSetting (SharingCapability)" -Level "API"
        $spSettings = Get-MgAdminSharepointSetting -ErrorAction Stop
        $sharingCap = $spSettings.SharingCapability
        Write-Dbg "TSP-003: SharingCapability='$sharingCap'" -Level "OK"
        if ($sharingCap -eq "Disabled" -or $sharingCap -eq "ExistingExternalUserSharingOnly") {
            Add-Finding -CheckId "TSP-003" -Domain "Teams & SharePoint" -Title "SharePoint Anonymous Sharing" `
                -Status "Pass" -CurrentValue "Anonymous sharing disabled" -ExpectedValue "Disabled or restricted" `
                -Severity "Critical" -Description "SharePoint anonymous (Anyone) sharing links are disabled or restricted." `
                -Recommendation "Maintain this restriction. If sharing is needed, use 'Specific People' or 'Existing guests' links that require authentication." `
                -Reference "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"
        } elseif ($sharingCap -eq "Anyone") {
            Add-Finding -CheckId "TSP-003" -Domain "Teams & SharePoint" -Title "SharePoint Anonymous Sharing" `
                -Status "Fail" -CurrentValue "Anyone links enabled" -ExpectedValue "Disabled" `
                -Severity "Critical" -Description "SharePoint 'Anyone' links are enabled. Files can be shared with anyone on the internet without authentication, risking sensitive data exposure." `
                -Recommendation "Change SharePoint sharing to at minimum 'New and existing guests' in the SharePoint admin center. Restrict 'Anyone' links for sensitive sites." `
                -Reference "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"
        } else {
            Add-Finding -CheckId "TSP-003" -Domain "Teams & SharePoint" -Title "SharePoint Anonymous Sharing" `
                -Status "Warning" -CurrentValue "Sharing capability: $sharingCap" -ExpectedValue "Disabled or restricted" `
                -Severity "Medium" -Description "SharePoint sharing is set to '$sharingCap'. Review to ensure this meets your data protection requirements." `
                -Recommendation "Evaluate sharing settings and restrict to the minimum required. Consider limiting sharing to authenticated users only." `
                -Reference "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"
        }
    } catch { Write-Err "TSP-003 failed: $_"; Write-Dbg "TSP-003 EXCEPTION: $_" -Level "ERROR" }

    # ── TSP-004  M365 Group Creation Restriction ──────────────────────────────
    try {
        Write-Dbg "TSP-004: Get-MgBetaDirectorySetting (Group.Unified settings)" -Level "API"
        $dirSettings = @()
        try {
            $dirSettings = Get-MgBetaDirectorySetting -ErrorAction Stop
            Write-Dbg "TSP-004: DirectorySettings found=$($dirSettings.Count)" -Level "OK"
        } catch {
            Write-Dbg "TSP-004: Get-MgBetaDirectorySetting failed — Microsoft.Graph.Beta module may be missing: $_" -Level "WARN"
        }
        $groupSettings = $dirSettings | Where-Object { $_.DisplayName -eq "Group.Unified" }
        $restricted = $false
        if ($groupSettings) {
            $enableGroupCreation = ($groupSettings.Values | Where-Object { $_.Name -eq "EnableGroupCreation" }).Value
            $restricted = $enableGroupCreation -eq "false"
            Write-Dbg "TSP-004: Group.Unified found. EnableGroupCreation='$enableGroupCreation'  Restricted=$restricted" -Level "OK"
        } else {
            Write-Dbg "TSP-004: Group.Unified directory setting not found — group creation is unrestricted (default)" -Level "WARN"
        }
        if ($restricted) {
            Add-Finding -CheckId "TSP-004" -Domain "Teams & SharePoint" -Title "M365 Group Creation Restriction" `
                -Status "Pass" -CurrentValue "Group creation restricted" -ExpectedValue "Restricted" `
                -Severity "Medium" -Description "Microsoft 365 Group creation is restricted to specific users/groups." `
                -Recommendation "Periodically review who has group creation permissions. Ensure a governance process exists for group provisioning." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/manage-creation-of-groups"
        } else {
            Add-Finding -CheckId "TSP-004" -Domain "Teams & SharePoint" -Title "M365 Group Creation Restriction" `
                -Status "Warning" -CurrentValue "All users can create groups/teams" -ExpectedValue "Restricted" `
                -Severity "Medium" -Description "Any user can create Microsoft 365 Groups (and Teams). This can lead to sprawl, ungoverned data repositories, and uncontrolled guest access." `
                -Recommendation "Restrict M365 Group creation to admins or a specific security group. Implement a group creation request process." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/manage-creation-of-groups"
        }
    } catch { Write-Err "TSP-004 failed: $_"; Write-Dbg "TSP-004 EXCEPTION: $_" -Level "ERROR" }

    Write-StatsSnapshot
    Write-Success "Teams & SharePoint analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 5  —  AUDIT & MONITORING
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-AuditMonitoringChecks {
    if ($SkipAudit) { Write-Skip "Audit & Monitoring checks skipped (–SkipAudit)."; return }
    if (-not $Script:GraphConnected) {
        Write-Skip "Graph not connected — skipping Audit checks."
        Write-Dbg "SKIPPED all Audit checks → GraphConnected=false. SecureScore/MaxSecureScore stay 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 5 — Audit & Monitoring"
    Write-Info "Analyzing Audit & Monitoring..."
    Write-DebugSection "Audit & Monitoring — API Calls"

    # ── AUD-001  Microsoft Secure Score ──────────────────────────────────────
    try {
        Write-Dbg "AUD-001: Get-MgSecuritySecureScore -Top 1 (requires SecurityEvents.Read.All)" -Level "API"
        $secureScores = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop
        if ($secureScores) {
            $current = [math]::Round($secureScores.CurrentScore, 0)
            $max     = [math]::Round($secureScores.MaxScore, 0)
            $pct     = if ($max -gt 0) { [math]::Round($current / $max * 100, 1) } else { 0 }
            Set-Stat "SecureScore"    $current
            Set-Stat "MaxSecureScore" $max
            Write-Dbg "AUD-001: SecureScore=$current/$max ($pct%)" -Level "OK"
            if ($pct -ge 70) {
                Add-Finding -CheckId "AUD-001" -Domain "Audit & Monitoring" -Title "Microsoft Secure Score" `
                    -Status "Pass" -CurrentValue "$current / $max ($pct%)" -ExpectedValue "≥70%" `
                    -Severity "Critical" -Description "Microsoft Secure Score is $pct% ($current/$max), indicating strong security controls." `
                    -Recommendation "Continue improving. Review recommendations in the Microsoft 365 Defender portal to push score higher." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score"
            } elseif ($pct -lt 30) {
                Add-Finding -CheckId "AUD-001" -Domain "Audit & Monitoring" -Title "Microsoft Secure Score" `
                    -Status "Fail" -CurrentValue "$current / $max ($pct%)" -ExpectedValue "≥70%" `
                    -Severity "Critical" -Description "Microsoft Secure Score is critically low at $pct% ($current/$max). Major security controls are missing." `
                    -Recommendation "Immediately review and implement high-impact recommendations in the Microsoft 365 Defender portal. Focus on identity and MFA improvements first." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score-improvement-actions"
            } else {
                Add-Finding -CheckId "AUD-001" -Domain "Audit & Monitoring" -Title "Microsoft Secure Score" `
                    -Status "Fail" -CurrentValue "$current / $max ($pct%)" -ExpectedValue "≥70%" `
                    -Severity "High" -Description "Microsoft Secure Score is $pct% ($current/$max). There are significant improvements available." `
                    -Recommendation "Review and prioritize improvement actions in the Microsoft 365 Defender portal. Focus on items with high points and low implementation effort." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score-improvement-actions"
            }
        } else {
            Write-Dbg "AUD-001: Get-MgSecuritySecureScore returned null/empty — tenant may not have Secure Score enabled yet." -Level "WARN"
            Add-Finding -CheckId "AUD-001" -Domain "Audit & Monitoring" -Title "Microsoft Secure Score" `
                -Status "Info" -CurrentValue "Score not available" -ExpectedValue "≥70%" `
                -Severity "Critical" -Description "Microsoft Secure Score data could not be retrieved. This may indicate the feature is not yet enabled or the account lacks SecurityEvents.Read.All permission." `
                -Recommendation "Ensure the account used for assessment has the Security Reader role. Check that Microsoft 365 Defender is enabled for the tenant." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score"
        }
    } catch { Write-Err "AUD-001 failed: $_"; Write-Dbg "AUD-001 EXCEPTION: $_  → SecureScore/MaxSecureScore stay 0" -Level "ERROR" }

    # ── AUD-002  Active Security Alerts ──────────────────────────────────────
    try {
        Write-Dbg "AUD-002: Get-MgSecurityAlert -Filter status eq active" -Level "API"
        $alerts = Get-MgSecurityAlert -Filter "status eq 'active'" -Top 50 -ErrorAction Stop
        $alertCount = @($alerts).Count
        Write-Dbg "AUD-002: Active alerts=$alertCount" -Level "OK"
        if ($alertCount -eq 0) {
            Add-Finding -CheckId "AUD-002" -Domain "Audit & Monitoring" -Title "Active Security Alerts" `
                -Status "Pass" -CurrentValue "0 active alerts" -ExpectedValue "0 active alerts" `
                -Severity "High" -Description "No active security alerts were found in Microsoft 365 Defender." `
                -Recommendation "Ensure alert notification rules are configured to notify security staff immediately of new alerts." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/investigate-alerts"
        } else {
            Add-Finding -CheckId "AUD-002" -Domain "Audit & Monitoring" -Title "Active Security Alerts" `
                -Status "Fail" -CurrentValue "$alertCount active alert(s)" -ExpectedValue "0 active alerts" `
                -Severity "High" -Description "$alertCount active security alert(s) found in Microsoft 365 Defender. These require immediate investigation." `
                -Recommendation "Investigate all active alerts in the Microsoft 365 Defender portal immediately. Triage by severity and assign to security team members." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/investigate-alerts"
        }
    } catch { Write-Err "AUD-002 failed: $_"; Write-Dbg "AUD-002 EXCEPTION: $_" -Level "ERROR" }

    # ── AUD-003  Unified Audit Log (Graph) ────────────────────────────────────
    try {
        Write-Dbg "AUD-003: Informational — audit log status delegated to EML-007" -Level "INFO"
        # Check via security/auditLogs
        Add-Finding -CheckId "AUD-003" -Domain "Audit & Monitoring" -Title "Unified Audit Log Status" `
            -Status "Info" -CurrentValue "Verified via EML-007 (if EXO connected)" -ExpectedValue "Enabled" `
            -Severity "Critical" -Description "Unified audit log status is checked via Exchange Online (EML-007). If Exchange is connected, refer to that finding." `
            -Recommendation "Ensure unified audit logging is enabled and retention is configured appropriately (90 days minimum, 1 year recommended)." `
            -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-solutions-overview"
    } catch { Write-Err "AUD-003 failed: $_"; Write-Dbg "AUD-003 EXCEPTION: $_" -Level "ERROR" }

    # ── AUD-004  SIEM / Diagnostic Settings ──────────────────────────────────
    try {
        Write-Dbg "AUD-004: Checking audit log availability via Graph auditLogs endpoint" -Level "API"
        # Check for Azure AD diagnostic settings via Graph
        $diagSettings = $null
        try {
            $diagSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1" -ErrorAction SilentlyContinue
        } catch {}

        Add-Finding -CheckId "AUD-004" -Domain "Audit & Monitoring" -Title "SIEM Integration / Diagnostic Settings" `
            -Status "Info" -CurrentValue "Manual verification required" -ExpectedValue "Configured" `
            -Severity "Medium" -Description "SIEM integration and Azure AD diagnostic settings cannot be fully verified via this API. Manual review required in the Azure portal under Entra ID > Diagnostic Settings." `
            -Recommendation "Configure Entra ID diagnostic settings to stream audit and sign-in logs to a SIEM (Azure Sentinel, Splunk, etc.) or Log Analytics workspace for centralized monitoring." `
            -Reference "https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-azure-monitor-logs"
    } catch { Write-Err "AUD-004 failed: $_"; Write-Dbg "AUD-004 EXCEPTION: $_" -Level "ERROR" }

    Write-StatsSnapshot
    Write-Success "Audit & Monitoring analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 6  —  OAUTH & APP SECURITY
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-OAuthChecks {
    if ($SkipOAuth) { Write-Skip "OAuth & App Security checks skipped (–SkipOAuth)."; return }
    if (-not $Script:GraphConnected) {
        Write-Skip "Graph not connected — skipping OAuth checks."
        Write-Dbg "SKIPPED all OAuth checks → GraphConnected=false. AppRegistrations/ServicePrincipals stay 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 6 — OAuth & App Security"
    Write-Info "Analyzing OAuth & App Security..."
    Write-DebugSection "OAuth & App Security — API Calls"

    # ── OAU-001  User App Registration Restriction ────────────────────────────
    try {
        Write-Dbg "OAU-001: Get-MgPolicyAuthorizationPolicy (AllowedToCreateApps)" -Level "API"
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $usersCanRegister = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps
        Write-Dbg "OAU-001: AllowedToCreateApps=$usersCanRegister" -Level "OK"
        if ($usersCanRegister -eq $false) {
            Add-Finding -CheckId "OAU-001" -Domain "OAuth & Apps" -Title "User App Registration" `
                -Status "Pass" -CurrentValue "App registration restricted to admins" -ExpectedValue "Restricted" `
                -Severity "Medium" -Description "Regular users cannot register applications. Only administrators can create app registrations." `
                -Recommendation "Maintain this restriction. Implement an app registration request process for users who need it." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added"
        } else {
            Add-Finding -CheckId "OAU-001" -Domain "OAuth & Apps" -Title "User App Registration" `
                -Status "Fail" -CurrentValue "All users can register apps" -ExpectedValue "Restricted to admins" `
                -Severity "Medium" -Description "All users can register application registrations. Malicious or misconfigured user-registered apps can lead to data exfiltration and OAuth token abuse." `
                -Recommendation "Disable user app registration: Set DefaultUserRolePermissions.AllowedToCreateApps to false in Entra ID User Settings." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added"
        }
    } catch { Write-Err "OAU-001 failed: $_"; Write-Dbg "OAU-001 EXCEPTION: $_" -Level "ERROR" }

    # ── OAU-002  Risky OAuth Grants ───────────────────────────────────────────
    try {
        Write-Dbg "OAU-002: Get-MgOauth2PermissionGrant -All (checking delegated high-risk scopes)" -Level "API"
        $riskyScopes = @("Mail.ReadWrite","Files.ReadWrite.All","Directory.ReadWrite.All",
                         "Mail.Read","Calendars.ReadWrite","Contacts.ReadWrite")
        $allGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
        Write-Dbg "OAU-002: Total OAuth grants=$($allGrants.Count)" -Level "OK"
        $riskyGrants = $allGrants | Where-Object {
            $scopeList = $_.Scope -split " "
            ($scopeList | Where-Object { $_ -in $riskyScopes }).Count -gt 0
        }
        Write-Dbg "OAU-002: High-risk grants=$($riskyGrants.Count)  (checked scopes: $($riskyScopes -join ', '))" -Level "OK"
        if ($riskyGrants.Count -gt 0) {
            $riskyGrants | ForEach-Object { Write-Dbg "  OAU-002: Risky grant — ClientId=$($_.ClientId)  Scopes=$($_.Scope)" -Level "WARN" }
        }
        if ($riskyGrants.Count -eq 0) {
            Add-Finding -CheckId "OAU-002" -Domain "OAuth & Apps" -Title "High-Risk OAuth Grants" `
                -Status "Pass" -CurrentValue "No high-risk OAuth grants found" -ExpectedValue "0 risky grants" `
                -Severity "High" -Description "No high-risk delegated OAuth permission grants were found." `
                -Recommendation "Periodically review all OAuth grants. Implement the admin consent workflow to control new grants." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent"
        } else {
            Add-Finding -CheckId "OAU-002" -Domain "OAuth & Apps" -Title "High-Risk OAuth Grants" `
                -Status "Fail" -CurrentValue "$($riskyGrants.Count) high-risk grant(s) found" -ExpectedValue "0 risky grants" `
                -Severity "High" -Description "$($riskyGrants.Count) application(s) have been granted high-risk OAuth permissions (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All). These can be used for data exfiltration." `
                -Recommendation "Review all high-risk OAuth grants in Entra ID > Enterprise Applications > Permissions. Revoke grants for unknown or unnecessary applications." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions"
        }
    } catch { Write-Err "OAU-002 failed: $_"; Write-Dbg "OAU-002 EXCEPTION: $_" -Level "ERROR" }

    # ── OAU-003 & OAU-004  App Registration Secrets ──────────────────────────
    try {
        Write-Dbg "OAU-003/004: Get-MgApplication -All (checking PasswordCredentials expiry)" -Level "API"
        $appRegs = Get-MgApplication -All -ErrorAction Stop
        Set-Stat "AppRegistrations" @($appRegs).Count
        Write-Dbg "OAU-003/004: AppRegistrations=$(@($appRegs).Count)" -Level "OK"
        $expiredApps  = @()
        $expiringApps = @()
        $now = Get-Date
        $soon = $now.AddDays(30)
        foreach ($app in $appRegs) {
            if ($app.PasswordCredentials) {
                foreach ($cred in $app.PasswordCredentials) {
                    if ($cred.EndDateTime -and [datetime]$cred.EndDateTime -lt $now) {
                        $expiredApps += "$($app.DisplayName) (expired $($cred.EndDateTime.ToString('yyyy-MM-dd')))"
                        Write-Dbg "  OAU-003: EXPIRED secret → App='$($app.DisplayName)' EndDate=$($cred.EndDateTime.ToString('yyyy-MM-dd'))" -Level "WARN"
                    } elseif ($cred.EndDateTime -and [datetime]$cred.EndDateTime -lt $soon) {
                        $expiringApps += "$($app.DisplayName) (expires $($cred.EndDateTime.ToString('yyyy-MM-dd')))"
                        Write-Dbg "  OAU-004: EXPIRING SOON secret → App='$($app.DisplayName)' EndDate=$($cred.EndDateTime.ToString('yyyy-MM-dd'))" -Level "WARN"
                    }
                }
            }
        }
        Write-Dbg "OAU-003: Expired secrets=$($expiredApps.Count)  Expiring soon=$($expiringApps.Count)" -Level "OK"
        if ($expiredApps.Count -eq 0) {
            Add-Finding -CheckId "OAU-003" -Domain "OAuth & Apps" -Title "Expired App Secrets/Certificates" `
                -Status "Pass" -CurrentValue "No expired secrets found" -ExpectedValue "0 expired" `
                -Severity "Medium" -Description "No expired application secrets or certificates were found." `
                -Recommendation "Implement a secret rotation schedule. Use Azure Key Vault or certificate-based auth instead of client secrets." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal"
        } else {
            Add-Finding -CheckId "OAU-003" -Domain "OAuth & Apps" -Title "Expired App Secrets/Certificates" `
                -Status "Fail" -CurrentValue "$($expiredApps.Count) expired secret(s)" -ExpectedValue "0 expired" `
                -Severity "Medium" -Description "$($expiredApps.Count) app registration(s) have expired secrets: $($expiredApps[0..4] -join '; ')$(if ($expiredApps.Count -gt 5) { ' and more...' })" `
                -Recommendation "Rotate expired secrets immediately. Apps with expired secrets may be broken and represent abandoned/unmanaged resources." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal"
        }
        if ($expiringApps.Count -eq 0) {
            Add-Finding -CheckId "OAU-004" -Domain "OAuth & Apps" -Title "App Secrets Expiring Soon (30 days)" `
                -Status "Pass" -CurrentValue "No secrets expiring in 30 days" -ExpectedValue "0 expiring soon" `
                -Severity "Medium" -Description "No application secrets are expiring within the next 30 days." `
                -Recommendation "Set up automated alerts for secret expiry. Consider using Workload Identity Federation instead of secrets." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation"
        } else {
            Add-Finding -CheckId "OAU-004" -Domain "OAuth & Apps" -Title "App Secrets Expiring Soon (30 days)" `
                -Status "Warning" -CurrentValue "$($expiringApps.Count) secret(s) expiring soon" -ExpectedValue "0 expiring soon" `
                -Severity "Medium" -Description "$($expiringApps.Count) app secret(s) expire within 30 days: $($expiringApps[0..4] -join '; ')$(if ($expiringApps.Count -gt 5) { ' and more...' })" `
                -Recommendation "Rotate these secrets before they expire to avoid application outages. Notify application owners immediately." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal"
        }
    } catch { Write-Err "OAU-003/004 failed: $_"; Write-Dbg "OAU-003/004 EXCEPTION: $_  → AppRegistrations stays 0" -Level "ERROR" }

    # ── OAU-005  Admin Consent Workflow ───────────────────────────────────────
    try {
        Write-Dbg "OAU-005: Get-MgPolicyAdminConsentRequestPolicy" -Level "API"
        $consentPolicies = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction Stop
        Write-Dbg "OAU-005: AdminConsentWorkflowEnabled=$($consentPolicies.IsEnabled)" -Level "OK"
        if ($consentPolicies.IsEnabled) {
            Add-Finding -CheckId "OAU-005" -Domain "OAuth & Apps" -Title "Admin Consent Workflow" `
                -Status "Pass" -CurrentValue "Admin consent workflow enabled" -ExpectedValue "Enabled" `
                -Severity "Medium" -Description "The admin consent workflow is enabled. Users can request admin consent for apps rather than granting permissions themselves." `
                -Recommendation "Ensure reviewers are configured and responsive. Monitor the consent request queue regularly." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-admin-consent-workflow"
        } else {
            Add-Finding -CheckId "OAU-005" -Domain "OAuth & Apps" -Title "Admin Consent Workflow" `
                -Status "Fail" -CurrentValue "Admin consent workflow disabled" -ExpectedValue "Enabled" `
                -Severity "Medium" -Description "The admin consent workflow is not enabled. Users who are blocked from granting consent have no way to request access through an approved process." `
                -Recommendation "Enable the admin consent workflow in Entra ID > Enterprise Applications > Consent and Permissions. Assign reviewers who can approve or deny requests." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-admin-consent-workflow"
        }
    } catch { Write-Err "OAU-005 failed: $_"; Write-Dbg "OAU-005 EXCEPTION: $_" -Level "ERROR" }

    # Get Service Principals count
    try {
        Write-Dbg "OAU: Get-MgServicePrincipal -Top 999 (for ServicePrincipals stat)" -Level "API"
        $sps = Get-MgServicePrincipal -Top 999 -ErrorAction SilentlyContinue
        Set-Stat "ServicePrincipals" @($sps).Count
        Write-Dbg "OAU: ServicePrincipals=$(@($sps).Count)" -Level "OK"
    } catch {
        Write-Dbg "OAU: Get-MgServicePrincipal failed: $_  → ServicePrincipals stays 0" -Level "WARN"
    }

    Write-StatsSnapshot
    Write-Success "OAuth & App Security analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        SCORING ENGINE
#══════════════════════════════════════════════════════════════════════════════════
function Compute-Scores {
    $passCount   = ($Script:Findings | Where-Object { $_.Status -eq "Pass"    }).Count
    $failCount   = ($Script:Findings | Where-Object { $_.Status -eq "Fail"    }).Count
    $warnCount   = ($Script:Findings | Where-Object { $_.Status -eq "Warning" }).Count
    $infoCount   = ($Script:Findings | Where-Object { $_.Status -eq "Info"    }).Count
    $totalChecks = $Script:Findings.Count
    $actionable  = $passCount + $failCount + $warnCount

    $toolScore = if ($actionable -gt 0) { [math]::Round($passCount / $actionable * 100) } else { 0 }
    $grade = switch ($toolScore) {
        { $_ -ge 80 } { "A" }
        { $_ -ge 65 } { "B" }
        { $_ -ge 50 } { "C" }
        { $_ -ge 35 } { "D" }
        default        { "F" }
    }

    $critFails = ($Script:Findings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }).Count
    $highFails = ($Script:Findings | Where-Object { $_.Status -in @("Fail","Warning") -and $_.Severity -eq "High" }).Count
    $warnings  = ($Script:Findings | Where-Object { $_.Status -eq "Warning" }).Count
    $rawRisk   = ($critFails * 20) + ($highFails * 8) + ($warnings * 2)
    $riskScore = [math]::Min(100, $rawRisk)
    $riskLevel = switch ($riskScore) {
        { $_ -ge 70 } { "CRITICAL" }
        { $_ -ge 40 } { "HIGH"     }
        { $_ -ge 20 } { "MEDIUM"   }
        default        { "LOW"      }
    }

    return [PSCustomObject]@{
        PassCount    = $passCount
        FailCount    = $failCount
        WarnCount    = $warnCount
        InfoCount    = $infoCount
        TotalChecks  = $totalChecks
        Actionable   = $actionable
        ToolScore    = $toolScore
        Grade        = $grade
        RiskScore    = $riskScore
        RiskLevel    = $riskLevel
        CritFails    = $critFails
        HighFails    = $highFails
    }
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        HTML REPORT GENERATOR
#══════════════════════════════════════════════════════════════════════════════════
function New-HtmlReport {
    param(
        [PSCustomObject]$Scores,
        [string]$OutputFile,
        [TimeSpan]$Duration
    )

    $scanDate  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $durationStr = "$([int]$Duration.TotalMinutes)m $($Duration.Seconds)s"
    $tsStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC+0")

    # Build domain stats
    $domains = @("Identity & MFA","Email Security","Data Protection","Teams & SharePoint","Audit & Monitoring","OAuth & Apps")
    $domainStatsJson = ($domains | ForEach-Object {
        $d = $_
        $dFindings = $Script:Findings | Where-Object { $_.Domain -eq $d }
        $p = ($dFindings | Where-Object { $_.Status -eq "Pass"    }).Count
        $f = ($dFindings | Where-Object { $_.Status -eq "Fail"    }).Count
        $w = ($dFindings | Where-Object { $_.Status -eq "Warning" }).Count
        '{"domain":"' + $d + '","pass":' + $p + ',"fail":' + $f + ',"warn":' + $w + '}'
    }) -join ","

    # Build findings JSON for JS
    $findingsJson = ($Script:Findings | ForEach-Object {
        $rec   = $_.Recommendation -replace '"','&quot;' -replace "'","&#39;"
        $desc  = $_.Description    -replace '"','&quot;' -replace "'","&#39;"
        $curr  = $_.CurrentValue   -replace '"','&quot;' -replace "'","&#39;"
        $exp   = $_.ExpectedValue  -replace '"','&quot;' -replace "'","&#39;"
        $ref   = $_.Reference      -replace '"','&quot;'
        $title = $_.Title          -replace '"','&quot;'
        '{"id":"' + $_.CheckId + '","domain":"' + $_.Domain + '","title":"' + $title + '","status":"' + $_.Status + '","current":"' + $curr + '","expected":"' + $exp + '","severity":"' + $_.Severity + '","description":"' + $desc + '","recommendation":"' + $rec + '","reference":"' + $ref + '"}'
    }) -join ","

    $riskColor = switch ($Scores.RiskLevel) {
        "CRITICAL" { "#c0392b" }
        "HIGH"     { "#e67e22" }
        "MEDIUM"   { "#f39c12" }
        "LOW"      { "#27ae60" }
    }

    $gradeColor = switch ($Scores.Grade) {
        "A" { "#27ae60" }
        "B" { "#2ecc71" }
        "C" { "#f39c12" }
        "D" { "#e67e22" }
        "F" { "#c0392b" }
    }

    $secureScoreDisplay = if ($Script:Stats.MaxSecureScore -gt 0) {
        "$($Script:Stats.SecureScore) / $($Script:Stats.MaxSecureScore) ($([math]::Round($Script:Stats.SecureScore/$Script:Stats.MaxSecureScore*100,1))%)"
    } else { "Not available" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$ReportTitle — $($Script:TenantDisplayName)</title>
<style>
:root {
  --primary:#8b7355;--primary-light:#a68b5b;--primary-dark:#5c4a2a;
  --danger:#c0392b;--warning:#f39c12;--success:#27ae60;--info:#8b7355;
  --bg:#f0f2f7;--card:#ffffff;--text:#1a1a2e;--text-muted:#6b7280;
  --border:#e5e7eb;--shadow:0 2px 15px rgba(0,0,0,0.08);
  --radius:12px;--sidebar-w:260px;
}
[data-theme="dark"] {
  --bg:#0f1117;--card:#1a1d2e;--text:#e2e8f0;--text-muted:#94a3b8;
  --border:#2d3748;--shadow:0 2px 15px rgba(0,0,0,0.4);
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background .3s,color .3s;}
a{color:var(--primary-light);text-decoration:none;}
a:hover{text-decoration:underline;}

/* ── TOP NAV ── */
.topbar{background:var(--primary-dark);color:#fff;padding:0 32px;display:flex;align-items:center;justify-content:space-between;height:64px;position:sticky;top:0;z-index:100;box-shadow:0 2px 10px rgba(0,0,0,.3);}
.brand{display:flex;align-items:center;gap:12px;}
.brand-logo{font-size:22px;font-weight:800;letter-spacing:-.5px;color:#fff;}
.brand-logo span{color:#64b5f6;}
.brand-sub{font-size:12px;opacity:.7;font-weight:400;}
.topbar-right{display:flex;align-items:center;gap:16px;}
.theme-btn{background:rgba(255,255,255,.15);border:none;color:#fff;border-radius:8px;padding:8px 14px;cursor:pointer;font-size:13px;transition:background .2s;}
.theme-btn:hover{background:rgba(255,255,255,.25);}
.confidential-badge{background:#c0392b;color:#fff;border-radius:6px;padding:4px 10px;font-size:11px;font-weight:700;letter-spacing:.5px;}

/* ── TAB NAV ── */
.tab-nav{background:var(--card);border-bottom:1px solid var(--border);display:flex;padding:0 32px;box-shadow:var(--shadow);}
.tab-btn{padding:16px 24px;border:none;background:none;cursor:pointer;font-size:14px;font-weight:600;color:var(--text-muted);border-bottom:3px solid transparent;transition:all .2s;margin-bottom:-1px;}
.tab-btn.active{color:var(--primary);border-bottom-color:var(--primary);}
.tab-btn:hover:not(.active){color:var(--text);border-bottom-color:var(--border);}

/* ── MAIN ── */
.main{max-width:1400px;margin:0 auto;padding:32px;}
.tab-content{display:none;}
.tab-content.active{display:block;}

/* ── CARDS ── */
.card{background:var(--card);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);border:1px solid var(--border);}
.card-title{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:16px;}

/* ── KPI GRID ── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px;}
.kpi-card{background:var(--card);border-radius:var(--radius);padding:20px 24px;border-left:4px solid;box-shadow:var(--shadow);}
.kpi-card.total  {border-color:var(--primary);}
.kpi-card.fail   {border-color:var(--danger);}
.kpi-card.warn   {border-color:var(--warning);}
.kpi-card.pass   {border-color:var(--success);}
.kpi-label{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--text-muted);margin-bottom:8px;font-weight:600;}
.kpi-value{font-size:36px;font-weight:800;line-height:1;}
.kpi-card.total .kpi-value {color:var(--primary);}
.kpi-card.fail  .kpi-value {color:var(--danger);}
.kpi-card.warn  .kpi-value {color:var(--warning);}
.kpi-card.pass  .kpi-value {color:var(--success);}

/* ── SCORE SECTION ── */
.score-section{display:grid;grid-template-columns:280px 1fr;gap:24px;margin-bottom:24px;}
.gauge-card{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 24px;}
.gauge-wrap{position:relative;width:180px;height:180px;}
.gauge-svg{transform:rotate(-90deg);}
.gauge-bg{fill:none;stroke:var(--border);stroke-width:16;}
.gauge-fill{fill:none;stroke-width:16;stroke-linecap:round;transition:stroke-dashoffset 1.5s cubic-bezier(.4,0,.2,1);stroke:var(--primary);}
.gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.gauge-pct{font-size:38px;font-weight:900;color:var(--text);}
.gauge-label{font-size:12px;color:var(--text-muted);font-weight:600;letter-spacing:.5px;}
.grade-badge{margin-top:16px;font-size:48px;font-weight:900;color:${gradeColor};}
.grade-text{font-size:12px;color:var(--text-muted);text-align:center;font-weight:600;}
.risk-card{display:flex;flex-direction:column;gap:16px;justify-content:center;}
.risk-level{display:inline-flex;align-items:center;gap:10px;padding:12px 24px;border-radius:100px;font-size:18px;font-weight:800;letter-spacing:.5px;width:fit-content;}
.risk-dot{width:14px;height:14px;border-radius:50%;background:#fff;}

/* ── DOMAIN BAR CHART ── */
.domain-bars{display:flex;flex-direction:column;gap:12px;}
.domain-row{display:grid;grid-template-columns:160px 1fr 80px;gap:12px;align-items:center;}
.domain-name{font-size:13px;font-weight:600;color:var(--text-muted);text-align:right;}
.bar-track{background:var(--border);border-radius:100px;height:22px;overflow:hidden;display:flex;}
.bar-seg{height:100%;transition:width 1s ease;border-radius:0;}
.bar-seg.pass{background:var(--success);}
.bar-seg.fail{background:var(--danger);}
.bar-seg.warn{background:var(--warning);}
.domain-counts{font-size:12px;color:var(--text-muted);}

/* ── TABLE ── */
.findings-controls{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px;align-items:center;}
.search-box{padding:9px 14px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:14px;width:220px;}
.filter-sel{padding:9px 14px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:14px;}
.btn{padding:9px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all .2s;}
.btn-export{background:var(--primary);color:#fff;}
.btn-export:hover{background:var(--primary-light);}
.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;}
th{padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted);font-weight:700;border-bottom:2px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap;}
th:hover{color:var(--primary);}
th .sort-arrow{opacity:.3;margin-left:4px;}
th.sorted .sort-arrow{opacity:1;}
td{padding:12px 16px;font-size:14px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr.finding-row:hover{background:rgba(44,62,140,.04);}
tr.detail-row{display:none;background:var(--bg);}
tr.detail-row.open{display:table-row;}
.detail-inner{padding:20px 24px;display:grid;grid-template-columns:1fr 1fr;gap:20px;}
.detail-section h4{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted);margin-bottom:8px;font-weight:700;}
.detail-section p,.detail-section .val{font-size:14px;line-height:1.6;color:var(--text);}
.expand-btn{background:none;border:none;cursor:pointer;color:var(--text-muted);font-size:16px;padding:4px;border-radius:4px;transition:transform .2s;}
.expand-btn.open{transform:rotate(90deg);}

/* ── STATUS & SEVERITY BADGES ── */
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:100px;font-size:11px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;white-space:nowrap;}
.badge-fail   {background:#fde8e8;color:#991b1b;}
.badge-warn   {background:#fef3c7;color:#92400e;}
.badge-pass   {background:#d1fae5;color:#065f46;}
.badge-info   {background:#f5ede0;color:#6b4f2a;}
.sev-critical {background:#fde8e8;color:#991b1b;}
.sev-high     {background:#fee2d5;color:#9a3412;}
.sev-medium   {background:#fef3c7;color:#92400e;}
.sev-low      {background:#d1fae5;color:#065f46;}
.sev-info     {background:#f5ede0;color:#6b4f2a;}
[data-theme="dark"] .badge-fail   {background:rgba(239,68,68,.2);color:#fca5a5;}
[data-theme="dark"] .badge-warn   {background:rgba(245,158,11,.2);color:#fcd34d;}
[data-theme="dark"] .badge-pass   {background:rgba(34,197,94,.2);color:#86efac;}
[data-theme="dark"] .badge-info   {background:rgba(180,140,100,.2);color:#d4a97a;}
[data-theme="dark"] .sev-critical {background:rgba(239,68,68,.2);color:#fca5a5;}
[data-theme="dark"] .sev-high     {background:rgba(249,115,22,.2);color:#fdba74;}
[data-theme="dark"] .sev-medium   {background:rgba(245,158,11,.2);color:#fcd34d;}
[data-theme="dark"] .sev-low      {background:rgba(34,197,94,.2);color:#86efac;}
[data-theme="dark"] .sev-info     {background:rgba(180,140,100,.2);color:#d4a97a;}

/* ── RECOMMENDATIONS ── */
.phase-block{margin-bottom:28px;}
.phase-header{display:flex;align-items:center;gap:12px;margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid var(--border);}
.phase-badge{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#fff;flex-shrink:0;}
.phase-1 .phase-badge{background:var(--danger);}
.phase-2 .phase-badge{background:#e67e22;}
.phase-3 .phase-badge{background:var(--warning);}
.phase-4 .phase-badge{background:var(--success);}
.phase-title{font-size:16px;font-weight:700;}
.rec-item{background:var(--card);border-radius:8px;padding:16px 20px;margin-bottom:10px;border:1px solid var(--border);border-left:4px solid;}
.phase-1 .rec-item{border-left-color:var(--danger);}
.phase-2 .rec-item{border-left-color:#e67e22;}
.phase-3 .rec-item{border-left-color:var(--warning);}
.phase-4 .rec-item{border-left-color:var(--success);}
.rec-title{font-weight:700;font-size:14px;margin-bottom:6px;display:flex;align-items:center;gap:8px;}
.rec-domain{font-size:11px;color:var(--text-muted);font-weight:600;}
.rec-text{font-size:13px;color:var(--text-muted);line-height:1.6;}
.rec-link{font-size:12px;margin-top:8px;}

/* ── TENANT INFO ── */
.info-table td{padding:12px 16px;font-size:14px;border-bottom:1px solid var(--border);}
.info-table td:first-child{font-weight:600;color:var(--text-muted);width:220px;font-size:13px;}
.info-table tr:last-child td{border-bottom:none;}

/* ── SECURE SCORE DISPLAY ── */
.ms-score-card{display:flex;align-items:center;gap:20px;padding:20px 24px;}
.ms-score-val{font-size:42px;font-weight:900;color:var(--primary);}
.ms-score-bar-wrap{flex:1;}
.ms-score-bar-track{background:var(--border);border-radius:100px;height:12px;overflow:hidden;}
.ms-score-bar-fill{height:100%;border-radius:100px;background:linear-gradient(90deg,var(--primary),#c4a882);transition:width 1.5s ease;}

/* ── FOOTER ── */
.footer{text-align:center;padding:32px;color:var(--text-muted);font-size:13px;border-top:1px solid var(--border);margin-top:40px;}
.footer strong{color:var(--text);}

/* ── LEGEND ── */
.legend{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:16px;}
.legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-muted);}
.legend-dot{width:12px;height:12px;border-radius:3px;}

@media(max-width:768px){
  .score-section{grid-template-columns:1fr;}
  .domain-row{grid-template-columns:120px 1fr 60px;}
  .detail-inner{grid-template-columns:1fr;}
  .topbar{padding:0 16px;}
  .main{padding:16px;}
}
</style>
</head>
<body>

<nav class="topbar">
  <div class="brand">
    <div>
      <div class="brand-logo">ConsultimIT</span></div>
      <div class="brand-sub">$ReportTitle</div>
    </div>
  </div>
  <div class="topbar-right">
    <span class="confidential-badge">CONFIDENTIAL</span>
    <button class="theme-btn" onclick="toggleTheme()">🌙 Dark Mode</button>
  </div>
</nav>

<div class="tab-nav">
  <button class="tab-btn active" onclick="showTab('dashboard',this)">📊 Dashboard</button>
  <button class="tab-btn" onclick="showTab('findings',this)">🔍 Findings</button>
  <button class="tab-btn" onclick="showTab('recommendations',this)">📋 Recommendations</button>
  <button class="tab-btn" onclick="showTab('tenantinfo',this)">🏢 Tenant Info</button>
</div>

<div class="main">

<!-- ════════════════════ DASHBOARD ════════════════════ -->
<div id="tab-dashboard" class="tab-content active">

  <div class="kpi-grid">
    <div class="kpi-card total"><div class="kpi-label">Total Checks</div><div class="kpi-value" data-target="$($Scores.TotalChecks)">0</div></div>
    <div class="kpi-card fail" ><div class="kpi-label">Failed</div>      <div class="kpi-value" data-target="$($Scores.FailCount)">0</div></div>
    <div class="kpi-card warn" ><div class="kpi-label">Warnings</div>    <div class="kpi-value" data-target="$($Scores.WarnCount)">0</div></div>
    <div class="kpi-card pass" ><div class="kpi-label">Passed</div>      <div class="kpi-value" data-target="$($Scores.PassCount)">0</div></div>
  </div>

  <div class="score-section">
    <div class="card gauge-card">
      <div class="card-title" style="text-align:center">Security Score</div>
      <div class="gauge-wrap">
        <svg class="gauge-svg" width="180" height="180" viewBox="0 0 180 180">
          <circle class="gauge-bg" cx="90" cy="90" r="74"/>
          <circle class="gauge-fill" id="gaugeFill" cx="90" cy="90" r="74"
            stroke-dasharray="465" stroke-dashoffset="465"/>
        </svg>
        <div class="gauge-center">
          <div class="gauge-pct" id="gaugePct">0%</div>
          <div class="gauge-label">SCORE</div>
        </div>
      </div>
      <div class="grade-badge">$($Scores.Grade)</div>
      <div class="grade-text">Grade</div>
    </div>

    <div class="card risk-card">
      <div class="card-title">Risk Assessment</div>
      <div class="risk-level" style="background:${riskColor};color:#fff;">
        <div class="risk-dot"></div>
        $($Scores.RiskLevel) RISK
      </div>
      <div style="font-size:14px;color:var(--text-muted);margin-top:8px;">
        Risk Score: <strong style="color:var(--text)">$($Scores.RiskScore)/100</strong>
      </div>
      <div style="font-size:13px;color:var(--text-muted);">
        $($Scores.CritFails) Critical Fail(s) · $($Scores.HighFails) High Fail/Warn(s) · $($Scores.WarnCount) Warning(s)
      </div>
      $(if ($Script:Stats.MaxSecureScore -gt 0) {
        $msPct = [math]::Round($Script:Stats.SecureScore/$Script:Stats.MaxSecureScore*100,0)
        @"
      <div style="margin-top:20px;">
        <div class="card-title">Microsoft Secure Score</div>
        <div class="ms-score-card" style="padding:0;margin-top:8px;">
          <div class="ms-score-val">$($Script:Stats.SecureScore)</div>
          <div class="ms-score-bar-wrap">
            <div style="font-size:13px;color:var(--text-muted);margin-bottom:6px;">$($Script:Stats.SecureScore) / $($Script:Stats.MaxSecureScore) ($msPct%)</div>
            <div class="ms-score-bar-track"><div class="ms-score-bar-fill" id="msScoreFill" style="width:0%"></div></div>
          </div>
        </div>
      </div>
"@
      })
    </div>
  </div>

  <div class="card">
    <div class="card-title">Security Posture by Domain</div>
    <div class="legend">
      <div class="legend-item"><div class="legend-dot" style="background:var(--success)"></div>Pass</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--danger)"></div>Fail</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--warning)"></div>Warning</div>
    </div>
    <div class="domain-bars" id="domainBars"></div>
  </div>

</div>

<!-- ════════════════════ FINDINGS ════════════════════ -->
<div id="tab-findings" class="tab-content">
  <div class="card">
    <div class="findings-controls">
      <input class="search-box" type="text" id="searchBox" placeholder="🔍 Search findings..." oninput="filterTable()">
      <select class="filter-sel" id="domainFilter" onchange="filterTable()">
        <option value="">All Domains</option>
        <option>Identity &amp; MFA</option>
        <option>Email Security</option>
        <option>Data Protection</option>
        <option>Teams &amp; SharePoint</option>
        <option>Audit &amp; Monitoring</option>
        <option>OAuth &amp; Apps</option>
      </select>
      <select class="filter-sel" id="statusFilter" onchange="filterTable()">
        <option value="">All Statuses</option>
        <option>Fail</option>
        <option>Warning</option>
        <option>Pass</option>
        <option>Info</option>
      </select>
      <select class="filter-sel" id="severityFilter" onchange="filterTable()">
        <option value="">All Severities</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
        <option>Informational</option>
      </select>
      <button class="btn btn-export" onclick="exportCSV()">⬇ Export CSV</button>
    </div>
    <div class="table-wrap">
      <table id="findingsTable">
        <thead>
          <tr>
            <th onclick="sortTable(0)">Check ID <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable(1)">Domain <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable(2)">Title <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable(3)">Status <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable(4)">Current Value <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable(5)">Severity <span class="sort-arrow">↕</span></th>
            <th style="width:40px"></th>
          </tr>
        </thead>
        <tbody id="findingsTbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ════════════════════ RECOMMENDATIONS ════════════════════ -->
<div id="tab-recommendations" class="tab-content">
  <div id="recContainer"></div>
</div>

<!-- ════════════════════ TENANT INFO ════════════════════ -->
<div id="tab-tenantinfo" class="tab-content">
  <div class="card">
    <div class="card-title">Tenant & Assessment Summary</div>
    <table class="info-table" style="width:100%">
      <tr><td>Tenant Name</td>       <td><strong>$($Script:TenantDisplayName)</strong></td></tr>
      <tr><td>Tenant ID</td>         <td>$($Script:TenantId)</td></tr>
      <tr><td>Scan Date</td>         <td>$scanDate</td></tr>
      <tr><td>Scan Duration</td>     <td>$durationStr</td></tr>
      <tr><td>Total Users</td>       <td>$($Script:Stats.TotalUsers)</td></tr>
      <tr><td>Enabled Users</td>     <td>$($Script:Stats.EnabledUsers)</td></tr>
      <tr><td>Guest Users</td>       <td>$($Script:Stats.GuestUsers)</td></tr>
      <tr><td>Global Admins</td>     <td>$($Script:Stats.GlobalAdmins)</td></tr>
      <tr><td>Stale Accounts (90d)</td><td>$($Script:Stats.StaleUsers)</td></tr>
      <tr><td>MFA Registration Rate</td><td>$($Script:Stats.MFAPct)%</td></tr>
      <tr><td>Admins Without MFA</td><td>$($Script:Stats.AdminNoMFA)</td></tr>
      <tr><td>CA Policies (Enabled)</td><td>$($Script:Stats.EnabledCAPolicies)</td></tr>
      <tr><td>DLP Policies</td>       <td>$($Script:Stats.DLPPolicies)</td></tr>
      <tr><td>App Registrations</td>  <td>$($Script:Stats.AppRegistrations)</td></tr>
      <tr><td>Microsoft Secure Score</td><td>$secureScoreDisplay</td></tr>
      <tr><td>Tool Secure Score</td>  <td>$($Scores.ToolScore)% (Grade: $($Scores.Grade))</td></tr>
      <tr><td>Risk Level</td>         <td><strong style="color:${riskColor}">$($Scores.RiskLevel)</strong> (Score: $($Scores.RiskScore)/100)</td></tr>
      <tr><td>Assessed By</td>        <td>Ranim Hassine — Consultim-IT</td></tr>
      <tr><td>Tool Version</td>       <td>ConsultimIT-O365-Assessment v1.0.0</td></tr>
    </table>
  </div>
</div>

</div><!-- /main -->

<div class="footer">
  <p><strong>Consultim-IT</strong> · Office 365 Security Assessment Tool v1.0.0 · consultim-it.com</p>
  <p style="margin-top:6px">Generated by Ranim Hassine · $tsStr</p>
  <p style="margin-top:6px;font-style:italic;font-size:11px">This report is confidential. For internal use only.</p>
</div>

<script>
// ── DATA ──────────────────────────────────────────────────
const FINDINGS = [$findingsJson];
const DOMAIN_STATS = [$domainStatsJson];
const TOOL_SCORE = $($Scores.ToolScore);
const MS_SCORE_PCT = $(if ($Script:Stats.MaxSecureScore -gt 0) { [math]::Round($Script:Stats.SecureScore/$Script:Stats.MaxSecureScore*100,0) } else { 0 });

// ── THEME ─────────────────────────────────────────────────
let dark = false;
function toggleTheme() {
  dark = !dark;
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : '');
  document.querySelector('.theme-btn').textContent = dark ? '☀️ Light Mode' : '🌙 Dark Mode';
}

// ── TABS ──────────────────────────────────────────────────
function showTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}

// ── COUNTER ANIMATION ─────────────────────────────────────
function animateCounter(el, target, duration=1200) {
  const start = Date.now();
  const tick = () => {
    const elapsed = Date.now() - start;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(ease * target);
    if (progress < 1) requestAnimationFrame(tick);
  };
  tick();
}

// ── GAUGE ANIMATION ───────────────────────────────────────
function animateGauge(score) {
  const circ = 2 * Math.PI * 74;
  const fill = document.getElementById('gaugeFill');
  const pctEl = document.getElementById('gaugePct');
  let start = null;
  const target = circ * (1 - score / 100);
  const animate = (ts) => {
    if (!start) start = ts;
    const progress = Math.min((ts - start) / 1500, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    const val = circ - ease * (circ - target);
    fill.setAttribute('stroke-dashoffset', val);
    pctEl.textContent = Math.round(ease * score) + '%';
    const color = score >= 70 ? '#27ae60' : score >= 50 ? '#f39c12' : '#c0392b';
    fill.style.stroke = color;
    if (progress < 1) requestAnimationFrame(animate);
  };
  requestAnimationFrame(animate);
}

// ── DOMAIN BARS ───────────────────────────────────────────
function buildDomainBars() {
  const container = document.getElementById('domainBars');
  DOMAIN_STATS.forEach(d => {
    const total = d.pass + d.fail + d.warn;
    if (total === 0) return;
    const pPct = (d.pass / total * 100).toFixed(1);
    const fPct = (d.fail / total * 100).toFixed(1);
    const wPct = (d.warn / total * 100).toFixed(1);
    const row = document.createElement('div');
    row.className = 'domain-row';
    row.innerHTML = '<div class="domain-name">' + d.domain + '</div>' +
      '<div class="bar-track">' +
        '<div class="bar-seg pass" data-width="' + pPct + '" style="width:0%"></div>' +
        '<div class="bar-seg fail" data-width="' + fPct + '" style="width:0%"></div>' +
        '<div class="bar-seg warn" data-width="' + wPct + '" style="width:0%"></div>' +
      '</div>' +
      '<div class="domain-counts" style="font-size:11px">' +
        '<span style="color:var(--success)">✓' + d.pass + '</span> ' +
        '<span style="color:var(--danger)">✗' + d.fail + '</span> ' +
        '<span style="color:var(--warning)">⚠' + d.warn + '</span>' +
      '</div>';
    container.appendChild(row);
    setTimeout(() => {
      row.querySelectorAll('.bar-seg').forEach(seg => {
        seg.style.width = seg.dataset.width + '%';
      });
    }, 300);
  });
}

// ── FINDINGS TABLE ────────────────────────────────────────
function statusBadge(s) {
  const cls = {Pass:'pass',Fail:'fail',Warning:'warn',Info:'info'}[s] || 'info';
  const icon = {Pass:'✓',Fail:'✗',Warning:'⚠',Info:'ℹ'}[s] || '';
  return '<span class="badge badge-' + cls + '">' + icon + ' ' + s + '</span>';
}
function severityBadge(s) {
  const cls = 'sev-' + s.toLowerCase();
  return '<span class="badge ' + cls + '">' + s + '</span>';
}

let sortCol = -1, sortAsc = true;
let currentRows = [];

function buildFindingsTable() {
  currentRows = FINDINGS;
  renderTable(currentRows);
}

function renderTable(rows) {
  const tbody = document.getElementById('findingsTbody');
  tbody.innerHTML = '';
  rows.forEach((f, i) => {
    const tr = document.createElement('tr');
    tr.className = 'finding-row';
    tr.innerHTML =
      '<td><code style="font-size:12px;background:var(--bg);padding:2px 6px;border-radius:4px">' + f.id + '</code></td>' +
      '<td style="font-size:13px">' + f.domain + '</td>' +
      '<td style="font-weight:600">' + f.title + '</td>' +
      '<td>' + statusBadge(f.status) + '</td>' +
      '<td style="font-size:13px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + f.current + '">' + f.current + '</td>' +
      '<td>' + severityBadge(f.severity) + '</td>' +
      '<td><button class="expand-btn" onclick="toggleDetail(this,' + i + ')">▶</button></td>';
    tbody.appendChild(tr);

    const detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.id = 'detail-' + i;
    detailTr.innerHTML = '<td colspan="7"><div class="detail-inner">' +
      '<div class="detail-section"><h4>Description</h4><p>' + f.description + '</p></div>' +
      '<div class="detail-section"><h4>Expected Value</h4><p class="val">' + f.expected + '</p></div>' +
      '<div class="detail-section"><h4>Recommendation</h4><p>' + f.recommendation + '</p></div>' +
      '<div class="detail-section"><h4>Reference</h4><p><a href="' + f.reference + '" target="_blank" rel="noopener">' + f.reference + '</a></p></div>' +
      '</div></td>';
    tbody.appendChild(detailTr);
  });
}

function toggleDetail(btn, idx) {
  btn.classList.toggle('open');
  document.getElementById('detail-' + idx).classList.toggle('open');
}

function filterTable() {
  const search = document.getElementById('searchBox').value.toLowerCase();
  const domain = document.getElementById('domainFilter').value;
  const status = document.getElementById('statusFilter').value;
  const sev    = document.getElementById('severityFilter').value;
  const filtered = FINDINGS.filter(f => {
    const matchSearch = !search || f.title.toLowerCase().includes(search) || f.id.toLowerCase().includes(search) || f.description.toLowerCase().includes(search);
    const matchDomain = !domain || f.domain === domain;
    const matchStatus = !status || f.status === status;
    const matchSev    = !sev    || f.severity === sev;
    return matchSearch && matchDomain && matchStatus && matchSev;
  });
  currentRows = filtered;
  renderTable(filtered);
}

function sortTable(col) {
  if (sortCol === col) sortAsc = !sortAsc;
  else { sortCol = col; sortAsc = true; }
  const keys = ['id','domain','title','status','current','severity'];
  const key = keys[col];
  const sorted = [...currentRows].sort((a,b) => {
    const av = (a[key]||'').toLowerCase(), bv = (b[key]||'').toLowerCase();
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  document.querySelectorAll('th .sort-arrow').forEach((a,i) => {
    a.textContent = i === col ? (sortAsc ? '↑' : '↓') : '↕';
  });
  renderTable(sorted);
}

function exportCSV() {
  const headers = ['CheckId','Domain','Title','Status','CurrentValue','ExpectedValue','Severity','Description','Recommendation','Reference'];
  const rows = FINDINGS.map(f => headers.map(h => {
    const map = {CheckId:'id',Domain:'domain',Title:'title',Status:'status',CurrentValue:'current',ExpectedValue:'expected',Severity:'severity',Description:'description',Recommendation:'recommendation',Reference:'reference'};
    const val = (f[map[h]]||'').replace(/"/g,'""');
    return '"' + val + '"';
  }).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ConsultimIT-O365-Findings.csv';
  a.click();
}

// ── RECOMMENDATIONS ───────────────────────────────────────
function buildRecommendations() {
  const phases = [
    { num:1, title:'Critical & Immediate',  filter: f => f.status==='Fail' && f.severity==='Critical' },
    { num:2, title:'High Priority',         filter: f => f.status!=='Pass' && f.status!=='Info' && f.severity==='High' },
    { num:3, title:'Medium Term',           filter: f => f.status!=='Pass' && f.status!=='Info' && f.severity==='Medium' },
    { num:4, title:'Best Practice',         filter: f => f.severity==='Low' || f.severity==='Informational' },
  ];
  const container = document.getElementById('recContainer');
  phases.forEach(phase => {
    const items = FINDINGS.filter(phase.filter);
    if (items.length === 0) return;
    const div = document.createElement('div');
    div.className = 'card phase-block phase-' + phase.num;
    div.innerHTML = '<div class="phase-header">' +
      '<div class="phase-badge">' + phase.num + '</div>' +
      '<div class="phase-title">Phase ' + phase.num + ' — ' + phase.title + ' (' + items.length + ' items)</div>' +
      '</div>' +
      items.map(f => '<div class="rec-item">' +
        '<div class="rec-title">' + f.title + '<span class="rec-domain">' + f.domain + '</span>' + severityBadge(f.severity) + '</div>' +
        '<div class="rec-text">' + f.recommendation + '</div>' +
        '<div class="rec-link"><a href="' + f.reference + '" target="_blank" rel="noopener">📖 Microsoft Documentation</a></div>' +
        '</div>'
      ).join('');
    container.appendChild(div);
  });
}

// ── INIT ──────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  // KPI counters
  document.querySelectorAll('.kpi-value[data-target]').forEach(el => {
    animateCounter(el, parseInt(el.dataset.target));
  });
  // Gauge
  setTimeout(() => animateGauge(TOOL_SCORE), 200);
  // MS Score bar
  const msBar = document.getElementById('msScoreFill');
  if (msBar) setTimeout(() => { msBar.style.width = MS_SCORE_PCT + '%'; }, 600);
  // Domain bars
  buildDomainBars();
  // Table
  buildFindingsTable();
  // Recommendations
  buildRecommendations();
});
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
    Write-Success "HTML report saved: $OutputFile"
}
#endregion

#region ─── MAIN ─────────────────────────────────────────────────────────────────
function Main {
    Write-Banner

    if ($DebugMode) {
        Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
        Write-Host "  │  DEBUG MODE ENABLED  — verbose API tracing active           │" -ForegroundColor Magenta
        Write-Host "  │  Color key:  STAT=Magenta  API=Cyan  OK=Green  WARN=Yellow  │" -ForegroundColor Magenta
        Write-Host "  │              ERROR=Red  INFO=DarkGray                       │" -ForegroundColor Magenta
        Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
        Write-Host ""
    }

    # Setup output dir
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Success "Output directory created: $OutputPath"
    }

    Test-RequiredModules
    Connect-Services

    # Run assessment domains
    Invoke-IdentityChecks
    Invoke-EmailChecks
    Invoke-DLPChecks
    Invoke-TeamsSharePointChecks
    Invoke-AuditMonitoringChecks
    Invoke-OAuthChecks

    # Compute scores
    $scores = Compute-Scores

    # Generate output files
    $ts = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
    $htmlFile = Join-Path $OutputPath "ConsultimIT-O365-Report_$ts.html"
    $jsonFile = Join-Path $OutputPath "ConsultimIT-O365-Findings_$ts.json"
    $duration = (Get-Date) - $StartTime

    New-HtmlReport -Scores $scores -OutputFile $htmlFile -Duration $duration

    # Export JSON
    $Script:Findings | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8 -Force
    Write-Success "JSON findings saved: $jsonFile"

    # Export debug log if debug mode was used
    $debugFile = $null
    if ($DebugMode -and $Script:DebugLog.Count -gt 0) {
        $debugFile = Join-Path $OutputPath "ConsultimIT-O365-DebugLog_$ts.txt"
        $lines = @("ConsultimIT-O365 Debug Log — Generated $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))", "=" * 70, "")
        foreach ($entry in $Script:DebugLog) {
            $lines += "[$($entry.Time)] [$($entry.Level.PadRight(5))]  $($entry.Message)"
        }
        $lines | Out-File -FilePath $debugFile -Encoding UTF8 -Force
        Write-Success "Debug log saved: $debugFile"

        # Print a ZERO-stats summary to console for quick triage
        Write-Host ""
        Write-Host "  ┌── ZERO-STATS TRIAGE ─────────────────────────────────────────" -ForegroundColor Magenta
        $anyZero = $false
        foreach ($key in ($Script:Stats.Keys | Sort-Object)) {
            if ($Script:Stats[$key] -eq 0) {
                $anyZero = $true
                Write-Host ("  │  {0,-24} = 0  ◄ check debug log for root cause" -f $key) -ForegroundColor Yellow
            }
        }
        if (-not $anyZero) {
            Write-Host "  │  All stats populated — no zeros detected." -ForegroundColor Green
        }
        Write-Host "  └──────────────────────────────────────────────────────────────" -ForegroundColor Magenta
    }

    # Disconnect
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Final summary
    $riskColor = switch ($scores.RiskLevel) {
        "CRITICAL" { "Red" }; "HIGH" { "Yellow" }; "MEDIUM" { "Yellow" }; "LOW" { "Green" }
    }
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║            ASSESSMENT COMPLETE                   ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host ("  ║  Tenant    : {0,-33}║" -f $Script:TenantDisplayName) -ForegroundColor Cyan
    Write-Host ("  ║  Duration  : {0,-33}║" -f "$([int]$duration.TotalMinutes)m $($duration.Seconds)s") -ForegroundColor Cyan
    Write-Host ("  ║  Score     : {0,-33}║" -f "$($scores.ToolScore)% (Grade $($scores.Grade))") -ForegroundColor Cyan
    Write-Host "  ║  Risk      : " -ForegroundColor Cyan -NoNewline
    Write-Host ("{0,-33}" -f $scores.RiskLevel) -ForegroundColor $riskColor -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("  ║  Checks    : {0} Total · {1} Fail · {2} Warn · {3} Pass · {4} Info" -f $scores.TotalChecks,$scores.FailCount,$scores.WarnCount,$scores.PassCount,$scores.InfoCount) -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host ("  ║  HTML  → {0,-41}║" -f (Split-Path $htmlFile -Leaf)) -ForegroundColor Cyan
    Write-Host ("  ║  JSON  → {0,-41}║" -f (Split-Path $jsonFile -Leaf)) -ForegroundColor Cyan
    if ($debugFile) {
        Write-Host ("  ║  DEBUG → {0,-41}║" -f (Split-Path $debugFile -Leaf)) -ForegroundColor Cyan
    }
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan

    if (-not $DebugMode) {
        Write-Host ""
        Write-Host "  TIP: Re-run with -DebugMode to trace why any stats show 0." -ForegroundColor DarkGray
        Write-Host "       .\ConsultimIT-O365-Assessment.ps1 -TenantId <id> -DebugMode" -ForegroundColor DarkGray
    }
    Write-Host ""
}

Main
#endregion
