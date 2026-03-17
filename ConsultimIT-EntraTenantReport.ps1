# ============================================================
# CONSULTIM-IT — ENTRA TENANT INTELLIGENCE REPORT
# ============================================================
# Usage:
#   .\ConsultimIT-EntraTenantReport.ps1 -TenantId "your-tenant-id"
# ============================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

$ErrorActionPreference = "Stop"

# ============================================================
# CONNECT TO MICROSOFT GRAPH
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor DarkCyan
Write-Host "  Consultim-IT — Entra Tenant Report" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host ">>> A browser window will open. Sign in and approve the permissions." -ForegroundColor Yellow
Write-Host ""

$scopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "Organization.Read.All",
    "Application.Read.All",
    "Policy.Read.All"
)

# Connect using device code flow so it works in any shell (no profile needed)
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome

Write-Host ""
Write-Host "Connected successfully." -ForegroundColor Green
Write-Host ""


# ============================================================
# TENANT INFO
# ============================================================

Write-Host "Collecting tenant information..." -ForegroundColor Cyan

$org = Get-MgOrganization | Select-Object -First 1

$tenantName        = $org.DisplayName
$tenantId          = $org.Id
$tenantCreated     = if ($org.CreatedDateTime) { ([datetime]$org.CreatedDateTime).ToString("yyyy-MM-dd") } else { "—" }
$country           = if ($org.CountryLetterCode) { $org.CountryLetterCode } else { "—" }
$verifiedDomains   = $org.VerifiedDomains

$initialDomain = ($verifiedDomains | Where-Object { $_.IsInitial -eq $true } | Select-Object -First 1).Name
if (-not $initialDomain) { $initialDomain = "—" }

$verifiedDomainCount = $verifiedDomains.Count

$reportGenerated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$startTime = Get-Date


# ============================================================
# FETCH USERS (beta endpoint for SignInActivity)
# ============================================================

Write-Host "Collecting users (this may take a moment)..." -ForegroundColor Cyan

$users = Get-MgBetaUser -All `
    -ConsistencyLevel eventual `
    -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime,AssignedLicenses,SignInActivity,Mail,JobTitle,Department"

Write-Host "  Users fetched: $($users.Count)" -ForegroundColor Gray


# ============================================================
# USER METRICS
# ============================================================

$totalUsers    = $users.Count
$enabledUsers  = ($users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -ne "Guest" }).Count
$guestUsers    = ($users | Where-Object { $_.UserType -eq "Guest" }).Count
$disabledUsers = ($users | Where-Object { $_.AccountEnabled -eq $false }).Count
$licensedUsers = ($users | Where-Object { $_.AssignedLicenses.Count -gt 0 }).Count
$unlicensedUsers = ($users | Where-Object { $_.AssignedLicenses.Count -eq 0 }).Count

$limitDate = (Get-Date).AddDays(-90)
$staleUsers = $users | Where-Object {
    $_.AccountEnabled -eq $true -and
    $_.SignInActivity -ne $null -and
    $_.SignInActivity.LastSignInDateTime -ne $null -and
    [datetime]$_.SignInActivity.LastSignInDateTime -lt $limitDate
}
$staleCount = $staleUsers.Count


# ============================================================
# ADMIN ACCOUNTS
# ============================================================

Write-Host "Collecting admin roles..." -ForegroundColor Cyan

$roles  = Get-MgDirectoryRole -All
$admins = @()

foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($m in $members) {
        if ($m.AdditionalProperties.userPrincipalName) {
            $admins += [PSCustomObject]@{
                UPN      = $m.AdditionalProperties.userPrincipalName
                RoleName = $role.DisplayName
            }
        }
    }
}

$adminCount     = ($admins.UPN | Select-Object -Unique).Count
$uniqueAdmins   = $admins | Sort-Object UPN -Unique


# ============================================================
# LICENCE SKUs
# ============================================================

Write-Host "Collecting licences..." -ForegroundColor Cyan

$skus = Get-MgSubscribedSku -All
$skuCount = $skus.Count


# ============================================================
# APPLICATIONS & SERVICE PRINCIPALS
# ============================================================

Write-Host "Collecting applications..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property "Id,DisplayName,CreatedDateTime,SignInAudience"
$appCount = $apps.Count

$sps  = Get-MgServicePrincipal -All -Property "Id,DisplayName,AppId,ServicePrincipalType,AccountEnabled"
$enterpriseApps = ($sps | Where-Object { $_.ServicePrincipalType -eq "Application" }).Count


# ============================================================
# CONDITIONAL ACCESS POLICIES
# ============================================================

Write-Host "Collecting Conditional Access policies..." -ForegroundColor Cyan

try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $caEnabled  = ($caPolicies | Where-Object { $_.State -eq "enabled" }).Count
    $caReport   = ($caPolicies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }).Count
    $caDisabled = ($caPolicies | Where-Object { $_.State -eq "disabled" }).Count
    $caTotal    = $caPolicies.Count
} catch {
    $caTotal = $caEnabled = $caReport = $caDisabled = 0
}


# ============================================================
# BUILD USER TABLE ROWS
# ============================================================

$userRows = ""
$counter  = 0

foreach ($u in ($users | Sort-Object DisplayName)) {
    $counter++
    if ($counter -gt 500) {
        $userRows += "<tr><td colspan='6' style='text-align:center;color:#888;font-style:italic;'>Showing first 500 users of $totalUsers total</td></tr>"
        break
    }

    $type    = if ($u.UserType -eq "Guest") { "<span class='badge badge-guest'>Guest</span>" } else { "<span class='badge badge-member'>Member</span>" }
    $status  = if ($u.AccountEnabled) { "<span class='badge badge-enabled'>Enabled</span>" } else { "<span class='badge badge-disabled'>Disabled</span>" }
    $lic     = if ($u.AssignedLicenses.Count -gt 0) { "<span class='badge badge-licensed'>Licensed</span>" } else { "<span class='badge badge-unlicensed'>Unlicensed</span>" }
    $lastSign = if ($u.SignInActivity -and $u.SignInActivity.LastSignInDateTime) {
        ([datetime]$u.SignInActivity.LastSignInDateTime).ToString("yyyy-MM-dd")
    } else { "—" }

    $rowClass = if ($counter % 2 -eq 0) { "row-even" } else { "row-odd" }

    $userRows += @"
<tr class='$rowClass'>
  <td>$($u.DisplayName)</td>
  <td>$($u.UserPrincipalName)</td>
  <td>$type</td>
  <td>$status</td>
  <td>$lic</td>
  <td>$lastSign</td>
</tr>
"@
}


# ============================================================
# BUILD ADMIN TABLE ROWS
# ============================================================

$adminRows = ""
$adminsByUPN = $admins | Group-Object UPN

foreach ($a in ($adminsByUPN | Sort-Object Name)) {
    $roles_list = ($a.Group.RoleName -join ", ")
    $adminRows += "<tr><td>$($a.Name)</td><td>$roles_list</td></tr>"
}


# ============================================================
# BUILD LICENCE TABLE ROWS
# ============================================================

$licenceRows = ""
foreach ($sku in ($skus | Sort-Object SkuPartNumber)) {
    $available = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
    $licenceRows += "<tr><td>$($sku.SkuPartNumber)</td><td>$($sku.PrepaidUnits.Enabled)</td><td>$($sku.ConsumedUnits)</td><td>$available</td></tr>"
}


# ============================================================
# BUILD DOMAIN TABLE ROWS
# ============================================================

$domainRows = ""
foreach ($d in ($verifiedDomains | Sort-Object Name)) {
    $flags = @()
    if ($d.IsDefault)  { $flags += "Default" }
    if ($d.IsInitial)  { $flags += "Initial" }
    if ($d.IsVerified) { $flags += "Verified" }
    $flagStr  = if ($flags.Count -gt 0) { $flags -join ", " } else { "—" }
    $domainRows += "<tr><td>$($d.Name)</td><td>$($d.Type)</td><td>$flagStr</td></tr>"
}


# ============================================================
# TIMING
# ============================================================

$endTime     = Get-Date
$duration    = $endTime - $startTime
$durationStr = "{0}m {1}s" -f [math]::Floor($duration.TotalMinutes), $duration.Seconds


# ============================================================
# GENERATE HTML REPORT
# ============================================================

Write-Host "Generating HTML report..." -ForegroundColor Cyan

$reportPath = if ($PSScriptRoot) { "$PSScriptRoot\Entra-Tenant-Report.html" } else { ".\Entra-Tenant-Report.html" }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Entra Tenant Intelligence Report</title>
<style>

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f0f0f0;
    color: #1a1a1a;
    font-size: 14px;
  }

  /* ── TOP BAR ── */
  .topbar {
    background: #1a1a1a;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 28px;
    height: 48px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .topbar-left { display: flex; align-items: center; gap: 14px; }
  .brand { font-size: 18px; font-weight: 700; letter-spacing: -0.5px; }
  .brand span { color: #f0a500; }
  .topbar-divider { color: #555; font-size: 18px; }
  .topbar-title { font-size: 13px; color: #aaa; }
  .topbar-right { display: flex; align-items: center; gap: 14px; font-size: 12px; color: #aaa; }
  .badge-confidential {
    background: #c0392b; color: #fff;
    padding: 3px 10px; border-radius: 3px;
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
  }

  /* ── TABS ── */
  .tabs {
    background: #fff;
    border-bottom: 1px solid #e0e0e0;
    display: flex;
    padding: 0 28px;
    gap: 0;
  }
  .tab {
    padding: 14px 22px;
    font-size: 13px;
    cursor: pointer;
    border-bottom: 3px solid transparent;
    color: #555;
    user-select: none;
    display: flex; align-items: center; gap: 7px;
  }
  .tab:hover { color: #1a1a1a; }
  .tab.active { border-bottom-color: #f0a500; color: #1a1a1a; font-weight: 600; }

  /* ── PAGES ── */
  .page { display: none; padding: 28px; }
  .page.active { display: block; }

  /* ── STAT CARDS ── */
  .cards-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    margin-bottom: 28px;
  }
  .card {
    background: #fff;
    border-radius: 8px;
    padding: 20px 24px;
    min-width: 170px;
    flex: 1;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    border-top: 4px solid #ddd;
    position: relative;
  }
  .card-label {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #888;
    margin-bottom: 10px;
  }
  .card-number {
    font-size: 38px;
    font-weight: 300;
    line-height: 1;
    color: #1a1a1a;
    margin-bottom: 6px;
  }
  .card-desc { font-size: 12px; color: #999; }

  .card-total    { border-top-color: #f0a500; }
  .card-enabled  { border-top-color: #27ae60; }
  .card-guest    { border-top-color: #2980b9; }
  .card-disabled { border-top-color: #c0392b; }
  .card-licensed { border-top-color: #8e44ad; }
  .card-unlicensed { border-top-color: #e67e22; }
  .card-stale    { border-top-color: #c0392b; }
  .card-admin    { border-top-color: #7f8c8d; }
  .card-apps     { border-top-color: #16a085; }
  .card-ca       { border-top-color: #2c3e50; }

  /* ── TWO COLUMN LAYOUT ── */
  .two-col { display: flex; gap: 18px; flex-wrap: wrap; }
  .two-col .panel { flex: 1; min-width: 300px; }

  /* ── PANELS ── */
  .panel {
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    overflow: hidden;
    margin-bottom: 18px;
  }
  .panel-header {
    padding: 14px 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #888;
    border-bottom: 1px solid #f0f0f0;
    background: #fafafa;
  }
  .panel-body { padding: 0; }

  /* ── KV TABLE (tenant details) ── */
  .kv-table { width: 100%; border-collapse: collapse; }
  .kv-table tr { border-bottom: 1px solid #f5f5f5; }
  .kv-table tr:last-child { border-bottom: none; }
  .kv-table td { padding: 10px 20px; font-size: 13px; }
  .kv-table td:first-child { color: #888; width: 55%; }
  .kv-table td:last-child { font-weight: 500; text-align: right; }

  /* ── DATA TABLES ── */
  .data-table { width: 100%; border-collapse: collapse; }
  .data-table thead th {
    background: #f5f5f5;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: #888;
    padding: 10px 16px;
    text-align: left;
    border-bottom: 1px solid #eee;
  }
  .data-table tbody td { padding: 10px 16px; font-size: 13px; border-bottom: 1px solid #f5f5f5; }
  .row-even { background: #fafafa; }
  .row-odd  { background: #fff; }
  .data-table tbody tr:hover { background: #f0f7ff; }

  /* ── BADGES ── */
  .badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .badge-member    { background: #e8f5e9; color: #27ae60; }
  .badge-guest     { background: #e3f2fd; color: #1565c0; }
  .badge-enabled   { background: #e8f5e9; color: #27ae60; }
  .badge-disabled  { background: #fdecea; color: #c0392b; }
  .badge-licensed  { background: #f3e5f5; color: #7b1fa2; }
  .badge-unlicensed { background: #fff3e0; color: #e65100; }
  .badge-caon      { background: #e8f5e9; color: #27ae60; }
  .badge-careport  { background: #fff3e0; color: #e65100; }
  .badge-caoff     { background: #f5f5f5; color: #888; }

  /* ── SEARCH BOX ── */
  .table-toolbar {
    padding: 12px 16px;
    border-bottom: 1px solid #f0f0f0;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .search-box {
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 6px 12px;
    font-size: 13px;
    width: 280px;
    outline: none;
  }
  .search-box:focus { border-color: #f0a500; }

  .page-title {
    font-size: 20px;
    font-weight: 600;
    margin-bottom: 20px;
    color: #1a1a1a;
  }

</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <div class="topbar-left">
    <div class="brand">Consultim-<span>IT</span></div>
    <div class="topbar-divider">|</div>
    <div class="topbar-title">Entra Tenant Intelligence Report</div>
  </div>
  <div class="topbar-right">
    <span>$tenantId</span>
    <span>&bull;</span>
    <span>$reportGenerated</span>
    <span class="badge-confidential">CONFIDENTIAL</span>
  </div>
</div>

<!-- TABS -->
<div class="tabs">
  <div class="tab active" onclick="showPage('overview',this)">&#128202; Overview</div>
  <div class="tab" onclick="showPage('licences',this)">&#128273; Licences</div>
  <div class="tab" onclick="showPage('users',this)">&#128101; Users</div>
  <div class="tab" onclick="showPage('admins',this)">&#128737; Admins</div>
  <div class="tab" onclick="showPage('apps',this)">&#128196; Applications</div>
  <div class="tab" onclick="showPage('ca',this)">&#128274; Conditional Access</div>
</div>


<!-- ══════════════════════════════════════════
     PAGE: OVERVIEW
══════════════════════════════════════════ -->
<div id="page-overview" class="page active">

  <div class="cards-grid">
    <div class="card card-total">
      <div class="card-label">Total Users</div>
      <div class="card-number">$totalUsers</div>
      <div class="card-desc">All account types</div>
    </div>
    <div class="card card-enabled">
      <div class="card-label">Enabled Members</div>
      <div class="card-number">$enabledUsers</div>
      <div class="card-desc">Active member accounts</div>
    </div>
    <div class="card card-guest">
      <div class="card-label">Guest Users</div>
      <div class="card-number">$guestUsers</div>
      <div class="card-desc">External collaborators</div>
    </div>
    <div class="card card-disabled">
      <div class="card-label">Disabled Accounts</div>
      <div class="card-number">$disabledUsers</div>
      <div class="card-desc">Inactive accounts</div>
    </div>
    <div class="card card-licensed">
      <div class="card-label">Licensed Users</div>
      <div class="card-number">$licensedUsers</div>
      <div class="card-desc">With &ge;1 licence assigned</div>
    </div>
    <div class="card card-unlicensed">
      <div class="card-label">Unlicensed</div>
      <div class="card-number">$unlicensedUsers</div>
      <div class="card-desc">No licence assigned</div>
    </div>
    <div class="card card-stale">
      <div class="card-label">Stale Accounts</div>
      <div class="card-number">$staleCount</div>
      <div class="card-desc">No sign-in in 90 days</div>
    </div>
    <div class="card card-admin">
      <div class="card-label">Admin Accounts</div>
      <div class="card-number">$adminCount</div>
      <div class="card-desc">Unique privileged users</div>
    </div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-header">Tenant Details</div>
      <div class="panel-body">
        <table class="kv-table">
          <tr><td>Organisation Name</td><td>$tenantName</td></tr>
          <tr><td>Tenant ID</td><td style="font-size:12px;font-family:monospace">$tenantId</td></tr>
          <tr><td>Initial Domain</td><td>$initialDomain</td></tr>
          <tr><td>Country</td><td>$country</td></tr>
          <tr><td>Tenant Created</td><td>$tenantCreated</td></tr>
          <tr><td>Verified Domains</td><td>$verifiedDomainCount</td></tr>
          <tr><td>Licence SKUs</td><td>$skuCount</td></tr>
          <tr><td>Registered Applications</td><td>$appCount</td></tr>
          <tr><td>Enterprise Applications</td><td>$enterpriseApps</td></tr>
          <tr><td>Conditional Access Policies</td><td>$caTotal</td></tr>
          <tr><td>Report Generated</td><td>$reportGenerated</td></tr>
          <tr><td>Scan Duration</td><td>$durationStr</td></tr>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">Verified Domains</div>
      <div class="panel-body">
        <table class="data-table">
          <thead><tr><th>Domain</th><th>Type</th><th>Flags</th></tr></thead>
          <tbody>$domainRows</tbody>
        </table>
      </div>
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════
     PAGE: LICENCES
══════════════════════════════════════════ -->
<div id="page-licences" class="page">

  <div class="cards-grid">
    <div class="card card-total">
      <div class="card-label">Licence SKUs</div>
      <div class="card-number">$skuCount</div>
      <div class="card-desc">Active subscription types</div>
    </div>
    <div class="card card-licensed">
      <div class="card-label">Licensed Users</div>
      <div class="card-number">$licensedUsers</div>
      <div class="card-desc">With &ge;1 licence assigned</div>
    </div>
    <div class="card card-unlicensed">
      <div class="card-label">Unlicensed Users</div>
      <div class="card-number">$unlicensedUsers</div>
      <div class="card-desc">No licence assigned</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">Licence SKU Breakdown</div>
    <div class="panel-body">
      <table class="data-table">
        <thead><tr><th>SKU / Product</th><th>Total Seats</th><th>Consumed</th><th>Available</th></tr></thead>
        <tbody>$licenceRows</tbody>
      </table>
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════
     PAGE: USERS
══════════════════════════════════════════ -->
<div id="page-users" class="page">

  <div class="cards-grid">
    <div class="card card-total"><div class="card-label">Total</div><div class="card-number">$totalUsers</div></div>
    <div class="card card-enabled"><div class="card-label">Enabled Members</div><div class="card-number">$enabledUsers</div></div>
    <div class="card card-guest"><div class="card-label">Guests</div><div class="card-number">$guestUsers</div></div>
    <div class="card card-disabled"><div class="card-label">Disabled</div><div class="card-number">$disabledUsers</div></div>
    <div class="card card-stale"><div class="card-label">Stale (90d)</div><div class="card-number">$staleCount</div></div>
  </div>

  <div class="panel">
    <div class="panel-header">User Directory</div>
    <div class="table-toolbar">
      <input class="search-box" type="text" id="userSearch" placeholder="Search users..." onkeyup="filterTable('userSearch','userTable')"/>
    </div>
    <div class="panel-body" style="overflow-x:auto">
      <table class="data-table" id="userTable">
        <thead>
          <tr>
            <th>Display Name</th>
            <th>UPN / Email</th>
            <th>Type</th>
            <th>Status</th>
            <th>Licence</th>
            <th>Last Sign-In</th>
          </tr>
        </thead>
        <tbody>$userRows</tbody>
      </table>
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════
     PAGE: ADMINS
══════════════════════════════════════════ -->
<div id="page-admins" class="page">

  <div class="cards-grid">
    <div class="card card-admin">
      <div class="card-label">Admin Accounts</div>
      <div class="card-number">$adminCount</div>
      <div class="card-desc">Unique privileged users</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">Privileged Role Assignments</div>
    <div class="table-toolbar">
      <input class="search-box" type="text" id="adminSearch" placeholder="Search admins..." onkeyup="filterTable('adminSearch','adminTable')"/>
    </div>
    <div class="panel-body" style="overflow-x:auto">
      <table class="data-table" id="adminTable">
        <thead><tr><th>User Principal Name</th><th>Roles</th></tr></thead>
        <tbody>$adminRows</tbody>
      </table>
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════
     PAGE: APPLICATIONS
══════════════════════════════════════════ -->
<div id="page-apps" class="page">

  <div class="cards-grid">
    <div class="card card-apps">
      <div class="card-label">Registered Apps</div>
      <div class="card-number">$appCount</div>
      <div class="card-desc">App registrations</div>
    </div>
    <div class="card card-apps">
      <div class="card-label">Enterprise Apps</div>
      <div class="card-number">$enterpriseApps</div>
      <div class="card-desc">Service principals (Application type)</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">App Registrations</div>
    <div class="table-toolbar">
      <input class="search-box" type="text" id="appSearch" placeholder="Search apps..." onkeyup="filterTable('appSearch','appTable')"/>
    </div>
    <div class="panel-body" style="overflow-x:auto">
      <table class="data-table" id="appTable">
        <thead><tr><th>Display Name</th><th>App ID</th><th>Sign-In Audience</th><th>Created</th></tr></thead>
        <tbody>
$(
    $appRows = ""
    $appCounter = 0
    foreach ($app in ($apps | Sort-Object DisplayName)) {
        $appCounter++
        if ($appCounter -gt 300) {
            $appRows += "<tr><td colspan='4' style='text-align:center;color:#888;font-style:italic;'>Showing first 300 of $appCount apps</td></tr>"
            break
        }
        $created = if ($app.CreatedDateTime) { ([datetime]$app.CreatedDateTime).ToString("yyyy-MM-dd") } else { "—" }
        $rc = if ($appCounter % 2 -eq 0) { "row-even" } else { "row-odd" }
        $appRows += "<tr class='$rc'><td>$($app.DisplayName)</td><td style='font-size:11px;font-family:monospace'>$($app.AppId)</td><td>$($app.SignInAudience)</td><td>$created</td></tr>"
    }
    $appRows
)
        </tbody>
      </table>
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════
     PAGE: CONDITIONAL ACCESS
══════════════════════════════════════════ -->
<div id="page-ca" class="page">

  <div class="cards-grid">
    <div class="card card-ca">
      <div class="card-label">Total Policies</div>
      <div class="card-number">$caTotal</div>
    </div>
    <div class="card card-enabled">
      <div class="card-label">Enforced</div>
      <div class="card-number">$caEnabled</div>
      <div class="card-desc">Enabled &amp; enforced</div>
    </div>
    <div class="card card-stale">
      <div class="card-label">Report-Only</div>
      <div class="card-number">$caReport</div>
      <div class="card-desc">Not enforced</div>
    </div>
    <div class="card card-unlicensed">
      <div class="card-label">Disabled</div>
      <div class="card-number">$caDisabled</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">Conditional Access Policies</div>
    <div class="panel-body" style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>Policy Name</th><th>State</th><th>Created</th><th>Modified</th></tr></thead>
        <tbody>
$(
    $caRows = ""
    $caCounter = 0
    if ($caTotal -gt 0) {
        foreach ($p in ($caPolicies | Sort-Object DisplayName)) {
            $caCounter++
            $rc = if ($caCounter % 2 -eq 0) { "row-even" } else { "row-odd" }
            $stateBadge = switch ($p.State) {
                "enabled"                             { "<span class='badge badge-caon'>Enabled</span>" }
                "enabledForReportingButNotEnforced"   { "<span class='badge badge-careport'>Report-Only</span>" }
                default                               { "<span class='badge badge-caoff'>Disabled</span>" }
            }
            $created  = if ($p.CreatedDateTime)  { ([datetime]$p.CreatedDateTime).ToString("yyyy-MM-dd")  } else { "—" }
            $modified = if ($p.ModifiedDateTime) { ([datetime]$p.ModifiedDateTime).ToString("yyyy-MM-dd") } else { "—" }
            $caRows += "<tr class='$rc'><td>$($p.DisplayName)</td><td>$stateBadge</td><td>$created</td><td>$modified</td></tr>"
        }
    } else {
        $caRows = "<tr><td colspan='4' style='text-align:center;color:#888;font-style:italic;'>No Conditional Access policies found or insufficient permissions</td></tr>"
    }
    $caRows
)
        </tbody>
      </table>
    </div>
  </div>

</div>


<!-- ══════════════════════════════════════════
     JAVASCRIPT
══════════════════════════════════════════ -->
<script>
  function showPage(id, el) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('page-' + id).classList.add('active');
    el.classList.add('active');
  }

  function filterTable(inputId, tableId) {
    var filter = document.getElementById(inputId).value.toLowerCase();
    var rows   = document.getElementById(tableId).getElementsByTagName('tr');
    for (var i = 1; i < rows.length; i++) {
      var text = rows[i].innerText.toLowerCase();
      rows[i].style.display = text.indexOf(filter) > -1 ? '' : 'none';
    }
  }
</script>

</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding utf8

$endTime     = Get-Date
$duration    = $endTime - $startTime
$durationStr = "{0}m {1}s" -f [math]::Floor($duration.TotalMinutes), $duration.Seconds

Write-Host ""
Write-Host "============================================" -ForegroundColor DarkGreen
Write-Host "  Report Generated Successfully!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor DarkGreen
Write-Host "  Path     : $reportPath" -ForegroundColor White
Write-Host "  Tenant   : $tenantName" -ForegroundColor White
Write-Host "  Users    : $totalUsers" -ForegroundColor White
Write-Host "  Admins   : $adminCount" -ForegroundColor White
Write-Host "  Duration : $durationStr" -ForegroundColor White
Write-Host "============================================" -ForegroundColor DarkGreen
Write-Host ""

# Auto-open the report in the default browser
Start-Process $reportPath