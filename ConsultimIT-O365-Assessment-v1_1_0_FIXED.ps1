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
    LicensedUsers     = 0
    UnlicensedUsers   = 0
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
    InitialDomain     = ""
    Country           = ""
    VerifiedDomains   = 0
    TenantCreated     = ""
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

    # ── Clear any stale Graph session first ─────────────────────────────────
    Write-Info "Clearing any existing Graph session to avoid token cache issues..."
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Dbg "Existing Graph session disconnected cleanly." -Level "OK"
    } catch {
        Write-Dbg "No existing Graph session to disconnect (this is fine)." -Level "INFO"
    }
    # Clear the SDK token cache files that cause 'Object reference not set' errors
    $tokenCachePaths = @(
        "$env:LOCALAPPDATA\.IdentityService",
        "$env:USERPROFILE\.graph",
        "$env:USERPROFILE\.mg"
    )
    foreach ($path in $tokenCachePaths) {
        if (Test-Path $path) {
            Write-Dbg "Clearing token cache: $path" -Level "INFO"
            try { Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

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
            $Script:Stats["InitialDomain"]   = ($org.VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -First 1).Name
            $Script:Stats["Country"]         = if ($org.CountryLetterCode) { $org.CountryLetterCode } else { "—" }
            $Script:Stats["VerifiedDomains"] = $org.VerifiedDomains.Count
            $Script:Stats["TenantCreated"]   = if ($org.CreatedDateTime) { ([datetime]$org.CreatedDateTime).ToString("yyyy-MM-dd") } else { "—" }
            $Script:OrgObject = $org
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
        Connect-ExchangeOnline -Device -Organization $Script:TenantId -ShowBanner:$false -ErrorAction Stop
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
    $allUsers     = @()
    $enabledUsers = @()
    $guestUsers   = @()
    $licensedUsers = @()

    try {
        Write-Dbg "API: Get-MgUser -All (v1.0) - basic properties" -Level "API"
        
        $allUsers = Get-MgUser -All `
            -ConsistencyLevel eventual `
            -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,AssignedLicenses `
            -ErrorAction Stop

        Write-Dbg "Get-MgUser returned $($allUsers.Count) users" -Level "OK"

        # ── Calculate basic counts first ─────────────────────────────────────
        $enabledUsers  = $allUsers | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq "Member" }
        $guestUsers    = $allUsers | Where-Object { $_.UserType -eq "Guest" }
        $licensedUsers = $allUsers | Where-Object { $_.AssignedLicenses.Count -gt 0 }

        Set-Stat "TotalUsers"      $allUsers.Count
        Set-Stat "EnabledUsers"    $enabledUsers.Count
        Set-Stat "GuestUsers"      $guestUsers.Count
        Set-Stat "LicensedUsers"   $licensedUsers.Count
        Set-Stat "UnlicensedUsers" ($allUsers.Count - $licensedUsers.Count)

        Write-Dbg "Basic counts calculated: Total=$($allUsers.Count) EnabledMembers=$($enabledUsers.Count) Guests=$($guestUsers.Count) Licensed=$($licensedUsers.Count)" -Level "OK"

        # ── Now try to enrich with SignInActivity (beta) for stale check only ──
        if ($DebugMode) { Write-Dbg "Attempting to fetch SignInActivity (beta)" -Level "API" }
        
        $staleCount = 0
        $cutoff = (Get-Date).AddDays(-90)

        try {
            $usersWithSignIn = Get-MgBetaUser -All `
                -ConsistencyLevel eventual `
                -Property Id,SignInActivity `
                -ErrorAction Stop

            Write-Dbg "Beta SignInActivity call returned $($usersWithSignIn.Count) objects" -Level "OK"

            # Match by Id and count stale
            $stale = $enabledUsers | ForEach-Object {
                $sid = $_.Id
                $signInInfo = $usersWithSignIn | Where-Object { $_.Id -eq $sid } | Select-Object -First 1
                
                if ($signInInfo -and $signInInfo.SignInActivity -and $signInInfo.SignInActivity.LastSignInDateTime) {
                    if ([datetime]$signInInfo.SignInActivity.LastSignInDateTime -lt $cutoff) {
                        return $_
                    }
                }
                $null   # not stale or no data
            } | Where-Object { $_ }

            $staleCount = $stale.Count
        }
        catch {
            Write-Dbg "Beta SignInActivity fetch failed: $_  → stale count = 0" -Level "WARN"
            $staleCount = 0
        }

        Set-Stat "StaleUsers" $staleCount

        if ($allUsers.Count -eq 0) {
            Write-Dbg "WARNING: No users returned from Get-MgUser. Check scopes (User.Read.All) or tenant state." -Level "WARN"
        }
    }
    catch {
        Write-Err "Failed to retrieve users (v1.0): $_"
        Write-Dbg "EXCEPTION in Get-MgUser: $_  → all user stats remain 0" -Level "ERROR"
    }

    # ── IDN-001  Stale accounts ──────────────────────────────────────────────
    try {
        $staleCount = $Script:Stats.StaleUsers
        Write-Dbg "IDN-001: Using precomputed stale=$staleCount" -Level "OK"
        if ($staleCount -eq 0) {
            Add-Finding -CheckId "IDN-001" -Domain "Identity & MFA" -Title "Stale User Accounts" `
                -Status "Pass" -CurrentValue "0 stale accounts" -ExpectedValue "0 stale accounts" `
                -Severity "Medium" -Description "No enabled user accounts have been inactive for 90+ days." `
                -Recommendation "Continue reviewing accounts quarterly." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins"
        } else {
            Add-Finding -CheckId "IDN-001" -Domain "Identity & MFA" -Title "Stale User Accounts" `
                -Status "Fail" -CurrentValue "$staleCount stale accounts" -ExpectedValue "0 stale accounts" `
                -Severity "Medium" -Description "$staleCount enabled accounts have had no sign-in activity in the last 90 days, increasing the attack surface." `
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
                -Severity "High" -Description "Safe Links policy is configured, providing real-time URL scanning." `
                -Recommendation "Ensure Safe Links is enabled for email, Teams, and Office apps. Set to 'On' for all protected users." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about"
        } else {
            Add-Finding -CheckId "EML-005" -Domain "Email Security" -Title "Safe Links Policy" `
                -Status "Fail" -CurrentValue "No Safe Links policy" -ExpectedValue "Policy exists" `
                -Severity "High" -Description "No Safe Links policy is configured. This requires Microsoft Defender for Office 365 (Plan 1 or 2). Without it, malicious URLs in emails can reach users." `
                -Recommendation "Configure Safe Links in Microsoft Defender for Office 365. Enable for email, Teams, and Office apps. Set action to 'Block'." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-policies-configure"
        }
    } catch { Write-Err "EML-005 failed: $_"; Write-Dbg "EML-005 EXCEPTION: $_" -Level "ERROR" }

    # ── EML-006  Anti-Malware Policy ──────────────────────────────────────────
    try {
        Write-Dbg "EML-006: Get-MalwareFilterPolicy" -Level "API"
        $malwarePolicies = Get-MalwareFilterPolicy -ErrorAction Stop
        $defaultMalware = $malwarePolicies | Where-Object { $_.IsDefault -eq $true }
        Write-Dbg "EML-006: $($malwarePolicies.Count) anti-malware policies  Default=$($defaultMalware.Name)" -Level "OK"
        if ($malwarePolicies) {
            Add-Finding -CheckId "EML-006" -Domain "Email Security" -Title "Anti-Malware Policy" `
                -Status "Pass" -CurrentValue "$($malwarePolicies.Count) policy/policies" -ExpectedValue "Policy exists" `
                -Severity "Medium" -Description "Anti-malware policies are configured." `
                -Recommendation "Ensure the default anti-malware policy is set to quarantine or delete malicious attachments. Enable zero-hour auto purge (ZAP)." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure"
        } else {
            Add-Finding -CheckId "EML-006" -Domain "Email Security" -Title "Anti-Malware Policy" `
                -Status "Fail" -CurrentValue "No anti-malware policy" -ExpectedValue "Policy exists" `
                -Severity "Medium" -Description "No anti-malware policy found. This is unusual as a default policy should exist." `
                -Recommendation "Create an anti-malware policy in Microsoft Defender for Office 365. Enable common attachment types filter and ZAP for malware." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure"
        }
    } catch { Write-Err "EML-006 failed: $_"; Write-Dbg "EML-006 EXCEPTION: $_" -Level "ERROR" }

    Write-StatsSnapshot
    Write-Success "Email Security analysis complete."
}
#endregion

#region ══════════════════════════════════════════════════════════════════════════
#        DOMAIN 3  —  DATA PROTECTION & DLP
#══════════════════════════════════════════════════════════════════════════════════
function Invoke-DLPChecks {
    if ($SkipDLP) { Write-Skip "Data Protection & DLP checks skipped (–SkipDLP)."; return }
    if (-not $Script:ExoConnected) {
        Write-Skip "Exchange Online not connected — skipping DLP checks."
        Write-Dbg "SKIPPED DLP checks → ExoConnected=false. DLPPolicies remains 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 3 — Data Protection & DLP"
    Write-Info "Analyzing DLP & Data Protection..."
    Write-DebugSection "Data Protection & DLP — API Calls"

    # ── DLP-001  DLP Policies ─────────────────────────────────────────────────
    try {
        Write-Dbg "DLP-001: Get-DlpPolicy (requires EXO + Compliance)" -Level "API"
        $dlpPolicies = Get-DlpPolicy -ErrorAction Stop
        $enabledDLP = $dlpPolicies | Where-Object { $_.Mode -ne "Disable" }
        Set-Stat "DLPPolicies" $enabledDLP.Count
        Write-Dbg "DLP-001: Total DLP policies=$($dlpPolicies.Count)  Enabled/Testing=$($enabledDLP.Count)" -Level "OK"
        if ($enabledDLP.Count -ge 3) {
            Add-Finding -CheckId "DLP-001" -Domain "Data Protection" -Title "DLP Policies" `
                -Status "Pass" -CurrentValue "$($enabledDLP.Count) active DLP policies" -ExpectedValue "≥3 active policies" `
                -Severity "High" -Description "$($enabledDLP.Count) DLP policies are active, helping prevent sensitive data leakage." `
                -Recommendation "Review DLP policies quarterly. Ensure coverage for credit cards, SSN, PII, and custom SITs." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp"
        } elseif ($enabledDLP.Count -eq 0) {
            Add-Finding -CheckId "DLP-001" -Domain "Data Protection" -Title "DLP Policies" `
                -Status "Fail" -CurrentValue "0 active DLP policies" -ExpectedValue "≥3 active policies" `
                -Severity "High" -Description "No active DLP policies found. Sensitive data (PII, financial info) can be shared freely via email, Teams, or SharePoint." `
                -Recommendation "Create DLP policies in Microsoft Purview. Start with templates for PII, PCI, HIPAA. Enable for Exchange, Teams, SharePoint." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-create-deploy-policy"
        } else {
            Add-Finding -CheckId "DLP-001" -Domain "Data Protection" -Title "DLP Policies" `
                -Status "Fail" -CurrentValue "$($enabledDLP.Count) active DLP policies" -ExpectedValue "≥3 active policies" `
                -Severity "Medium" -Description "Only $($enabledDLP.Count) active DLP policy/policies. Insufficient to cover common data leakage scenarios." `
                -Recommendation "Add more DLP policies to cover endpoints, Teams chats, and SharePoint sites. Use custom sensitive info types for organization-specific data." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-create-deploy-policy"
        }
    } catch { Write-Err "DLP-001 failed (may require P1/P2): $_"; Write-Dbg "DLP-001 EXCEPTION: $_  → DLPPolicies stays 0" -Level "ERROR" }

    # ── DLP-002  Sensitivity Labels ───────────────────────────────────────────
    try {
        Write-Dbg "DLP-002: Get-Label (Compliance)" -Level "API"
        $labels = Get-Label -ErrorAction Stop
        $enabledLabels = $labels | Where-Object { $_.Mode -eq "Enable" -or $_.Disabled -eq $false }
        Write-Dbg "DLP-002: Total labels=$($labels.Count)  Enabled=$($enabledLabels.Count)" -Level "OK"
        if ($enabledLabels.Count -ge 5) {
            Add-Finding -CheckId "DLP-002" -Domain "Data Protection" -Title "Sensitivity Labels" `
                -Status "Pass" -CurrentValue "$($enabledLabels.Count) enabled labels" -ExpectedValue "≥5 enabled labels" `
                -Severity "High" -Description "$($enabledLabels.Count) sensitivity labels are enabled for data classification." `
                -Recommendation "Auto-apply labels based on content. Integrate with DLP policies for enforcement." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels"
        } else {
            Add-Finding -CheckId "DLP-002" -Domain "Data Protection" -Title "Sensitivity Labels" `
                -Status "Fail" -CurrentValue "$($enabledLabels.Count) enabled labels" -ExpectedValue "≥5 enabled labels" `
                -Severity "High" -Description "Only $($enabledLabels.Count) sensitivity label(s) enabled. Without labels, data cannot be classified or protected consistently." `
                -Recommendation "Create sensitivity labels in Microsoft Purview (e.g., Public, Internal, Confidential, Highly Confidential). Enable for email, files, and meetings." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/create-sensitivity-labels"
        }
    } catch { Write-Err "DLP-002 failed: $_"; Write-Dbg "DLP-002 EXCEPTION: $_" -Level "ERROR" }

    # ── DLP-003  Retention Policies ───────────────────────────────────────────
    try {
        Write-Dbg "DLP-003: Get-RetentionCompliancePolicy" -Level "API"
        $retPolicies = Get-RetentionCompliancePolicy -ErrorAction Stop
        $enabledRet = $retPolicies | Where-Object { $_.Enabled -eq $true }
        Write-Dbg "DLP-003: Total retention policies=$($retPolicies.Count)  Enabled=$($enabledRet.Count)" -Level "OK"
        if ($enabledRet.Count -ge 2) {
            Add-Finding -CheckId "DLP-003" -Domain "Data Protection" -Title "Retention Policies" `
                -Status "Pass" -CurrentValue "$($enabledRet.Count) enabled policies" -ExpectedValue "≥2 enabled policies" `
                -Severity "Medium" -Description "$($enabledRet.Count) retention policies are enabled to manage data lifecycle." `
                -Recommendation "Ensure retention covers email, Teams, SharePoint. Review purge actions for compliance." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/retention"
        } else {
            Add-Finding -CheckId "DLP-003" -Domain "Data Protection" -Title "Retention Policies" `
                -Status "Fail" -CurrentValue "$($enabledRet.Count) enabled policies" -ExpectedValue "≥2 enabled policies" `
                -Severity "Medium" -Description "Only $($enabledRet.Count) retention policy/policies enabled. Data may not be retained or deleted according to compliance requirements." `
                -Recommendation "Create retention policies in Microsoft Purview. Set retention periods for different workloads (e.g., 7 years for financial data)." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/create-retention-policies"
        }
    } catch { Write-Err "DLP-003 failed: $_"; Write-Dbg "DLP-003 EXCEPTION: $_" -Level "ERROR" }

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
        Write-Dbg "SKIPPED Teams/SP checks → GraphConnected=false." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 4 — Teams & SharePoint"
    Write-Info "Analyzing Teams & SharePoint..."
    Write-DebugSection "Teams & SharePoint — API Calls"

    # ── TSP-001  Teams External Access ────────────────────────────────────────
    try {
        Write-Dbg "TSP-001: Get-MgTeamworkTeamSetting" -Level "API"
        $teamsSettings = Get-MgTeamworkTeamSetting -ErrorAction Stop
        $extAccess = $teamsSettings.AllowExternalAccess
        Write-Dbg "TSP-001: ExternalAccess=$extAccess" -Level "OK"
        if (-not $extAccess) {
            Add-Finding -CheckId "TSP-001" -Domain "Teams & SharePoint" -Title "Teams External Access" `
                -Status "Pass" -CurrentValue "External access disabled" -ExpectedValue "Disabled or restricted" `
                -Severity "Medium" -Description "External access to Teams is disabled, reducing risk of unauthorized collaboration." `
                -Recommendation "If external access is needed, restrict to allowlisted domains only." `
                -Reference "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access"
        } else {
            Add-Finding -CheckId "TSP-001" -Domain "Teams & SharePoint" -Title "Teams External Access" `
                -Status "Warning" -CurrentValue "External access enabled" -ExpectedValue "Disabled or restricted" `
                -Severity "Medium" -Description "External access to Teams is enabled, allowing federation with any Teams tenant." `
                -Recommendation "Disable external access or restrict to specific allowed domains in the Teams admin center." `
                -Reference "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access"
        }
    } catch { Write-Err "TSP-001 failed: $_"; Write-Dbg "TSP-001 EXCEPTION: $_" -Level "ERROR" }

    # ── TSP-002  SharePoint External Sharing ──────────────────────────────────
    try {
        Write-Dbg "TSP-002: Get-MgSite -SiteId root + Get-MgPolicySharePointSetting" -Level "API"
        $spSettings = Get-MgPolicySharePointSetting -ErrorAction Stop
        $sharingLevel = $spSettings.SharingCapability
        Write-Dbg "TSP-002: SharingCapability=$sharingLevel" -Level "OK"
        if ($sharingLevel -eq "Disabled" -or $sharingLevel -eq "ExistingExternalUserSharingOnly") {
            Add-Finding -CheckId "TSP-002" -Domain "Teams & SharePoint" -Title "SharePoint External Sharing" `
                -Status "Pass" -CurrentValue "Sharing: $sharingLevel" -ExpectedValue "Disabled or restricted" `
                -Severity "High" -Description "SharePoint external sharing is restricted ($sharingLevel), preventing unauthorized data exfiltration." `
                -Recommendation "Monitor sharing audit logs. Consider enabling guest access reviews." `
                -Reference "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"
        } else {
            Add-Finding -CheckId "TSP-002" -Domain "Teams & SharePoint" -Title "SharePoint External Sharing" `
                -Status "Fail" -CurrentValue "Sharing: $sharingLevel" -ExpectedValue "Disabled or restricted" `
                -Severity "High" -Description "SharePoint external sharing is set to $sharingLevel, allowing broad external access to documents." `
                -Recommendation "Set SharePoint sharing to 'Existing guests only' or disable entirely in the SharePoint admin center." `
                -Reference "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"
        }
    } catch { Write-Err "TSP-002 failed: $_"; Write-Dbg "TSP-002 EXCEPTION: $_" -Level "ERROR" }

    # ── TSP-003  Teams Meeting Policies ───────────────────────────────────────
    try {
        Write-Dbg "TSP-003: Get-MgGroupPolicyAssignment -Filter 'policy/type eq ''CsTeamsMeetingPolicy'''" -Level "API"
        $meetingPolicies = Get-MgGroupPolicyAssignment -Filter "policy/type eq 'CsTeamsMeetingPolicy'" -ErrorAction Stop
        $hasPolicy = $meetingPolicies.Count -gt 0
        Write-Dbg "TSP-003: Meeting policy assignments=$($meetingPolicies.Count)" -Level "OK"
        if ($hasPolicy) {
            Add-Finding -CheckId "TSP-003" -Domain "Teams & SharePoint" -Title "Teams Meeting Policies" `
                -Status "Pass" -CurrentValue "$($meetingPolicies.Count) policy assignments" -ExpectedValue "Policies assigned" `
                -Severity "Medium" -Description "Teams meeting policies are assigned, allowing control over meeting features." `
                -Recommendation "Disable anonymous join and meeting recording if not required. Enable watermarking for sensitive meetings." `
                -Reference "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-overview"
        } else {
            Add-Finding -CheckId "TSP-003" -Domain "Teams & SharePoint" -Title "Teams Meeting Policies" `
                -Status "Fail" -CurrentValue "No meeting policies assigned" -ExpectedValue "Policies assigned" `
                -Severity "Medium" -Description "No Teams meeting policies are assigned. Default global policy allows broad features like anonymous join." `
                -Recommendation "Create and assign Teams meeting policies in the Teams admin center. Restrict who can record, present, or join anonymously." `
                -Reference "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-overview"
        }
    } catch { Write-Err "TSP-003 failed: $_"; Write-Dbg "TSP-003 EXCEPTION: $_" -Level "ERROR" }

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
        Write-Dbg "SKIPPED Audit checks → GraphConnected=false. SecureScore/MaxSecureScore remain 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 5 — Audit & Monitoring"
    Write-Info "Analyzing Audit & Monitoring..."
    Write-DebugSection "Audit & Monitoring — API Calls"

    # ── AUD-001  Audit Log Retention ──────────────────────────────────────────
    try {
        Write-Dbg "AUD-001: Get-MgAuditLogDirectoryAuditLogRetention" -Level "API"
        $auditRetention = Get-MgAuditLogDirectoryAuditLogRetention -ErrorAction Stop
        $retPeriod = if ($auditRetention) { $auditRetention.RetentionPeriod } else { 0 }
        Write-Dbg "AUD-001: Audit retention period=$retPeriod days" -Level "OK"
        if ($retPeriod -ge 365) {
            Add-Finding -CheckId "AUD-001" -Domain "Audit & Monitoring" -Title "Audit Log Retention" `
                -Status "Pass" -CurrentValue "$retPeriod days" -ExpectedValue "≥365 days" `
                -Severity "Medium" -Description "Audit logs are retained for $retPeriod days, sufficient for investigations." `
                -Recommendation "Consider exporting logs to Azure Sentinel or a SIEM for longer retention." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-retention-policies"
        } else {
            Add-Finding -CheckId "AUD-001" -Domain "Audit & Monitoring" -Title "Audit Log Retention" `
                -Status "Fail" -CurrentValue "$retPeriod days" -ExpectedValue "≥365 days" `
                -Severity "Medium" -Description "Audit logs are only retained for $retPeriod days. Short retention hinders incident response and compliance audits." `
                -Recommendation "Create an audit log retention policy in Microsoft Purview for at least 1 year (requires E5/P2 license)." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-retention-policies"
        }
    } catch { Write-Err "AUD-001 failed (requires E5/P2): $_"; Write-Dbg "AUD-001 EXCEPTION: $_" -Level "ERROR" }

    # ── AUD-002  Microsoft Secure Score ───────────────────────────────────────
    try {
        Write-Dbg "AUD-002: Get-MgSecuritySecureScore -Top 1" -Level "API"
        $secureScore = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop
        if ($secureScore) {
            Set-Stat "SecureScore"    $secureScore.CurrentScore
            Set-Stat "MaxSecureScore" $secureScore.MaxScore
            $ssPct = [math]::Round($secureScore.CurrentScore / $secureScore.MaxScore * 100, 1)
            Write-Dbg "AUD-002: SecureScore=$($secureScore.CurrentScore)/$($secureScore.MaxScore) ($ssPct%)" -Level "OK"
            if ($ssPct -ge 70) {
                Add-Finding -CheckId "AUD-002" -Domain "Audit & Monitoring" -Title "Microsoft Secure Score" `
                    -Status "Pass" -CurrentValue "$($secureScore.CurrentScore)/$($secureScore.MaxScore) ($ssPct%)" -ExpectedValue "≥70%" `
                    -Severity "Medium" -Description "Secure Score is $ssPct%, indicating good implementation of recommended controls." `
                    -Recommendation "Review and implement top improvement actions in the Microsoft Defender portal." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score"
            } else {
                Add-Finding -CheckId "AUD-002" -Domain "Audit & Monitoring" -Title "Microsoft Secure Score" `
                    -Status "Fail" -CurrentValue "$($secureScore.CurrentScore)/$($secureScore.MaxScore) ($ssPct%)" -ExpectedValue "≥70%" `
                    -Severity "Medium" -Description "Secure Score is only $ssPct%. Many recommended security controls are not implemented." `
                    -Recommendation "Prioritize high-impact actions in the Secure Score dashboard. Aim for 70%+ by addressing identity and device recommendations first." `
                    -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score"
            }
        } else {
            Write-Dbg "AUD-002: No Secure Score data returned" -Level "WARN"
        }
    } catch { Write-Err "AUD-002 failed: $_"; Write-Dbg "AUD-002 EXCEPTION: $_  → SecureScore stays 0" -Level "ERROR" }

    # ── AUD-003  Alert Policies ───────────────────────────────────────────────
    try {
        Write-Dbg "AUD-003: Get-MgSecurityAlertPolicy" -Level "API"
        $alertPolicies = Get-MgSecurityAlertPolicy -ErrorAction Stop
        $enabledAlerts = $alertPolicies | Where-Object { $_.Enabled -eq $true }
        Write-Dbg "AUD-003: Total alert policies=$($alertPolicies.Count)  Enabled=$($enabledAlerts.Count)" -Level "OK"
        if ($enabledAlerts.Count -ge 10) {
            Add-Finding -CheckId "AUD-003" -Domain "Audit & Monitoring" -Title "Alert Policies" `
                -Status "Pass" -CurrentValue "$($enabledAlerts.Count) enabled alerts" -ExpectedValue "≥10 enabled alerts" `
                -Severity "Medium" -Description "$($enabledAlerts.Count) security alert policies are enabled." `
                -Recommendation "Configure notifications for high-severity alerts. Integrate with SIEM." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/alerts-overview"
        } else {
            Add-Finding -CheckId "AUD-003" -Domain "Audit & Monitoring" -Title "Alert Policies" `
                -Status "Fail" -CurrentValue "$($enabledAlerts.Count) enabled alerts" -ExpectedValue "≥10 enabled alerts" `
                -Severity "Medium" -Description "Only $($enabledAlerts.Count) security alert policies enabled. Insufficient monitoring for threats." `
                -Recommendation "Enable default alert policies in Microsoft Defender for Office 365 and Entra ID Protection. Create custom alerts for anomalous activities." `
                -Reference "https://learn.microsoft.com/en-us/microsoft-365/security/defender/alerts-overview"
        }
    } catch { Write-Err "AUD-003 failed: $_"; Write-Dbg "AUD-003 EXCEPTION: $_" -Level "ERROR" }

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
        Write-Dbg "SKIPPED OAuth checks → GraphConnected=false. AppRegistrations/ServicePrincipals remain 0." -Level "WARN"
        return
    }

    Write-SectionHeader "Domain 6 — OAuth & App Security"
    Write-Info "Analyzing OAuth & App Security..."
    Write-DebugSection "OAuth & App Security — API Calls"

    # ── OAU-001  App Registrations ────────────────────────────────────────────
    try {
        Write-Dbg "OAU-001: Get-MgApplication -All" -Level "API"
        $apps = Get-MgApplication -All -ErrorAction Stop
        Set-Stat "AppRegistrations" $apps.Count
        Write-Dbg "OAU-001: AppRegistrations=$($apps.Count)" -Level "OK"
        if ($apps.Count -le 20) {
            Add-Finding -CheckId "OAU-001" -Domain "OAuth & Apps" -Title "App Registrations Count" `
                -Status "Pass" -CurrentValue "$($apps.Count) app registrations" -ExpectedValue "≤20 registrations" `
                -Severity "Medium" -Description "The tenant has $($apps.Count) app registrations, which is reasonable." `
                -Recommendation "Review app registrations quarterly. Delete unused ones." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals"
        } else {
            Add-Finding -CheckId "OAU-001" -Domain "OAuth & Apps" -Title "App Registrations Count" `
                -Status "Warning" -CurrentValue "$($apps.Count) app registrations" -ExpectedValue "≤20 registrations" `
                -Severity "Medium" -Description "$($apps.Count) app registrations exist. Excessive apps increase attack surface." `
                -Recommendation "Audit and remove unused app registrations. Use Entra ID's app governance features." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals"
        }
    } catch { Write-Err "OAU-001 failed: $_"; Write-Dbg "OAU-001 EXCEPTION: $_  → AppRegistrations stays 0" -Level "ERROR" }

    # ── OAU-002  User Consent Settings ────────────────────────────────────────
    try {
        Write-Dbg "OAU-002: Get-MgPolicyAuthorizationPolicy" -Level "API"
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $userConsent = $authPolicy.PermissionGrantPolicyIdsAssignedToDefaultUserRole
        $consentSetting = if ($userConsent -contains "microsoft-user-default-low") { "Low-risk permissions" }
                          elseif ($userConsent -contains "microsoft-user-default-legacy") { "All permissions" }
                          else { "Disabled" }
        Write-Dbg "OAU-002: User consent setting=$consentSetting" -Level "OK"
        if ($consentSetting -eq "Disabled") {
            Add-Finding -CheckId "OAU-002" -Domain "OAuth & Apps" -Title "User Consent for Apps" `
                -Status "Pass" -CurrentValue "User consent disabled" -ExpectedValue "Disabled" `
                -Severity "High" -Description "Users cannot consent to apps themselves, preventing risky permissions grants." `
                -Recommendation "Enable the admin consent workflow for users to request approvals." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent"
        } else {
            Add-Finding -CheckId "OAU-002" -Domain "OAuth & Apps" -Title "User Consent for Apps" `
                -Status "Fail" -CurrentValue "User consent: $consentSetting" -ExpectedValue "Disabled" `
                -Severity "High" -Description "Users can consent to apps for $consentSetting. This allows phishing apps to gain access via user consent." `
                -Recommendation "Disable user consent in Entra ID > Enterprise Applications > Consent and Permissions. Use group-based consent if needed." `
                -Reference "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent"
        }
    } catch { Write-Err "OAU-002 failed: $_"; Write-Dbg "OAU-002 EXCEPTION: $_" -Level "ERROR" }

    # ── OAU-003/004  Expired/Expiring App Secrets ─────────────────────────────
    try {
        Write-Dbg "OAU-003/004: Get-MgApplication -All -Property Id,DisplayName,PasswordCredentials" -Level "API"
        $appsWithCreds = Get-MgApplication -All -Property Id,DisplayName,PasswordCredentials -ErrorAction Stop
        $expiredApps = @()
        $expiringApps = @()
        $now = Get-Date
        $soon = $now.AddDays(30)
        foreach ($app in $appsWithCreds) {
            foreach ($cred in $app.PasswordCredentials) {
                if ($cred.EndDateTime -lt $now) { $expiredApps += $app.DisplayName }
                elseif ($cred.EndDateTime -lt $soon) { $expiringApps += $app.DisplayName }
            }
        }
        $expiredApps = $expiredApps | Sort-Object -Unique
        $expiringApps = $expiringApps | Sort-Object -Unique
        Write-Dbg "OAU-003: Expired apps=$($expiredApps.Count)" -Level "OK"
        Write-Dbg "OAU-004: Expiring soon=$($expiringApps.Count)" -Level "OK"
        if ($expiredApps.Count -eq 0) {
            Add-Finding -CheckId "OAU-003" -Domain "OAuth & Apps" -Title "Expired App Secrets/Certificates" `
                -Status "Pass" -CurrentValue "0 expired secrets" -ExpectedValue "0 expired" `
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
        Write-Dbg "OAU: Get-MgServicePrincipal -All (for ServicePrincipals stat)" -Level "API"
        $sps = Get-MgServicePrincipal -All -ErrorAction SilentlyContinue
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
    $passCount   = @($Script:Findings | Where-Object { $_.Status -eq "Pass"    }).Count
    $failCount   = @($Script:Findings | Where-Object { $_.Status -eq "Fail"    }).Count
    $warnCount   = @($Script:Findings | Where-Object { $_.Status -eq "Warning" }).Count
    $infoCount   = @($Script:Findings | Where-Object { $_.Status -eq "Info"    }).Count
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

    $critFails = @($Script:Findings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }).Count
    $highFails = @($Script:Findings | Where-Object { $_.Status -in @("Fail","Warning") -and $_.Severity -eq "High" }).Count
    $warnings  = @($Script:Findings | Where-Object { $_.Status -eq "Warning" }).Count
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
        $dFindings = @($Script:Findings | Where-Object { $_.Domain -eq $d })
        $p = @($dFindings | Where-Object { $_.Status -eq "Pass"    }).Count
        $f = @($dFindings | Where-Object { $_.Status -eq "Fail"    }).Count
        $w = @($dFindings | Where-Object { $_.Status -eq "Warning" }).Count
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
.risk-level{display:inline-flex;align-items:center;gap:10px;padding:12px
"@
}