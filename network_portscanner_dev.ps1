<#
.SYNOPSIS
  Ping and TCP-port scan a list of IPs/ranges concurrently, print concise console results, and optionally save CSV (default) or JSON.

.PARAMETER IPs
  - Comma-separated IPs/CIDRs (e.g. "192.168.1.0/24,10.0.0.5"), OR
  - Path to a text file with one IP or CIDR per line (lines starting with # ignored)

.PARAMETER Ports
  Comma-separated TCP ports or ranges (e.g. "80,443-445,8080") — quote this argument

.PARAMETER OutputFile
  Optional path for results. If no .csv/.json extension is present, it’s appended based on -Json.

.PARAMETER Json
  Export JSON if set; otherwise CSV is used (default).

.PARAMETER Ping
  If set, ping hosts in parallel. Port scans always run.

.NOTES
  - IPv4 only
  - ~250 ms per-port TCP connect timeout
  - Windows PowerShell 5.1 uses runspace pool; PowerShell 7+ uses ForEach-Object -Parallel
  - Timestamps are Unix epoch seconds derived from the host's local time zone
#>

param(
  [Parameter(Mandatory=$true, Position=0)]
  [string] $IPs,

  [Parameter(Mandatory=$true, Position=1)]
  [string] $Ports,

  [Parameter(Mandatory=$false, Position=2)]
  [string] $OutputFile,

  [switch] $Json,
  [switch] $Ping
)

# ===== Version check =====
$psVersion = $PSVersionTable.PSVersion
$psMajor   = $psVersion.Major
Write-Host "Detected PowerShell version $psVersion" -ForegroundColor Cyan

# ===== Regex (precompiled) =====
$rangeRegex      = [regex]'^\s*(\d+)\s*-\s*(\d+)\s*$'
$singlePortRegex = [regex]'^\s*\d+\s*$'
$cidrRegex       = [regex]'^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
$ipRegex         = [regex]'^(?:\d{1,3}\.){3}\d{1,3}$'

function Expand-PortList {
  param([string]$portString)
  foreach ($p in $portString.Split(',')) {
    $p = $p.Trim()
    if ($rangeRegex.IsMatch($p)) {
      $m = $rangeRegex.Match($p)
      $start = [int]$m.Groups[1].Value
      $end   = [int]$m.Groups[2].Value
      for ($i=$start; $i -le $end; $i++) { $i }
    }
    elseif ($singlePortRegex.IsMatch($p)) { [int]$p }
    else { Write-Warning "Skipping invalid port entry: '$p'" }
  }
}

function Get-IPRangeFromCIDR {
  param([string]$cidr)
  $parts = $cidr.Split('/')
  if ($parts.Count -ne 2) { throw "Invalid CIDR: $cidr" }
  $ipString     = $parts[0]
  $prefixLength = [int]$parts[1]
  if ($prefixLength -lt 0 -or $prefixLength -gt 32) { throw "Invalid prefix in $cidr" }

  $bytes  = [System.Net.IPAddress]::Parse($ipString).GetAddressBytes()
  [Array]::Reverse($bytes)
  $ipUint = [BitConverter]::ToUInt32($bytes,0)

  if     ($prefixLength -eq 0)  { $mask = [uint32]0 }
  elseif ($prefixLength -eq 32) { $mask = [uint32]0xFFFFFFFF }
  else {
    $shift = 32 - $prefixLength
    $mask  = [uint32]((( [uint64]4294967295 ) -shl $shift) -band 4294967295)
  }

  $network   = $ipUint -band $mask
  $hostCount = [uint32]((-bnot $mask) -band 0xFFFFFFFF)
  $broadcast = if ($prefixLength -eq 32) { $network }
               elseif ($prefixLength -eq 0) { [uint32]0xFFFFFFFF }
               else { $network + $hostCount }

  for ($addr=$network; $addr -le $broadcast; $addr++) {
    $b = [BitConverter]::GetBytes([uint32]$addr)
    [Array]::Reverse($b)
    [System.Net.IPAddress]::new($b).ToString()
  }
}

function Ensure-OutputPath {
  param(
    [string] $Path,
    [switch] $AsJson
  )
  if (-not $Path) { return $null }
  $ext = [System.IO.Path]::GetExtension($Path)
  $desiredExt = if ($AsJson) { '.json' } else { '.csv' }
  if ([string]::IsNullOrWhiteSpace($ext) -or ($ext.ToLower() -notin @('.csv','.json'))) {
    return "$Path$desiredExt"
  }
  return $Path
}

function Export-Results {
  param(
    [Parameter(Mandatory)] $PingRecords,   # objects: Type='Ping', Host, Status ('SUCCESS'/'FAIL'), Timestamp (epoch)
    [Parameter(Mandatory)] $PortRecords,   # objects: Type='Port', Host, Port, Status ('OPEN'/'CLOSED'), Timestamp (epoch)
    [string] $OutputPath,
    [switch] $AsJson,
    [switch] $IncludeFailures               # include closed/failed rows when -Verbose is used
  )

  if (-not $OutputPath) {
    $fmt = if ($AsJson) { 'JSON' } else { 'CSV' }
    Write-Host "No output file specified. (Format preference: $fmt)" -ForegroundColor Yellow
    return
  }

  $OutputPath = Ensure-OutputPath -Path $OutputPath -AsJson:$AsJson

  if ($AsJson) {
    # Build grouped JSON per IP, include failures only when requested
    $byIp = @{}
    foreach ($p in $PingRecords) {
      if (-not $IncludeFailures -and $p.Status -ne 'SUCCESS') { continue }
      if (-not $byIp.ContainsKey($p.Host)) {
        $byIp[$p.Host] = [ordered]@{
          ip    = $p.Host
          ping  = @()
          ports = @()
        }
      }
      $status = if ($p.Status -eq 'SUCCESS') { 'success' } else { 'fail' }
      $byIp[$p.Host].ping += @{ timestamp = [string]$p.Timestamp; status = $status }
    }
    foreach ($r in $PortRecords) {
      if (-not $IncludeFailures -and $r.Status -ne 'OPEN') { continue }
      if (-not $byIp.ContainsKey($r.Host)) {
        $byIp[$r.Host] = [ordered]@{
          ip    = $r.Host
          ping  = @()
          ports = @()
        }
      }
      $status = if ($r.Status -eq 'OPEN') { 'open' } else { 'closed' }
      $byIp[$r.Host].ports += @{ port = [int]$r.Port; status = $status; timestamp = [string]$r.Timestamp }
    }

    $arr = @()
    foreach ($k in ($byIp.Keys | Sort-Object { [System.Version]$_ })) { $arr += $byIp[$k] }

    $arr | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "Results saved to $OutputPath (format: JSON)" -ForegroundColor Cyan
  }
  else {
    # CSV (flat): combine, filter, select consistent columns
    $all = @()
    if ($IncludeFailures) {
      $all += $PingRecords
      $all += $PortRecords
    } else {
      $all += $PingRecords | Where-Object { $_.Status -eq 'SUCCESS' }
      $all += $PortRecords | Where-Object { $_.Status -eq 'OPEN' }
    }
    $flat = $all | Select-Object @{n='Type';e={$_.Type}},
                            @{n='Host';e={$_.Host}},
                            @{n='Port';e={if ($_.PSObject.Properties.Match('Port').Count){$_.Port}else{$null}}},
                            @{n='Status';e={$_.Status}},
                            @{n='Timestamp';e={$_.Timestamp}} |
            Sort-Object Host,Port,Type
    $flat | Export-Csv -LiteralPath $OutputPath -Encoding UTF8 -NoTypeInformation
    Write-Host "Results saved to $OutputPath ($($flat.Count) rows; format: CSV)" -ForegroundColor Cyan
  }
}

# Helper: epoch seconds using host local time zone (timezone-agnostic, but derived from local clock)
function Get-LocalEpoch {
  [int64][System.DateTimeOffset]::Now.ToUnixTimeSeconds()
}

# ===== Ingest IPs (file OR comma list) =====
Write-Host "Expanding IP list..." -ForegroundColor Cyan
$rawEntries = @()

if (Test-Path -LiteralPath $IPs) {
  Write-Host "  Reading IPs from file: $IPs" -ForegroundColor Yellow
  $fileLines = Get-Content -LiteralPath $IPs -ErrorAction Stop
  foreach ($line in $fileLines) {
    $t = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($t)) { continue }
    if ($t -match '^\s*#') { continue }   # comments
    foreach ($segment in $t.Split(',')) {
      $seg = $segment.Trim()
      if ($seg) { $rawEntries += $seg }
    }
  }
}
else {
  $rawEntries = $IPs.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

$allIPs = @(); $ranges = @()
foreach ($entry in $rawEntries) {
  if ($cidrRegex.IsMatch($entry)) {
    Write-Host "  CIDR $entry"
    $exp = @(Get-IPRangeFromCIDR $entry)
    $ranges += [PSCustomObject]@{ CIDR=$entry; Range="$($exp[0])-$($exp[-1])"; Count=$exp.Count }
    $allIPs += $exp
  }
  elseif ($ipRegex.IsMatch($entry)) { $allIPs += $entry }
  else { Write-Warning "Invalid IP/CIDR: $entry" }
}

# Numeric sort & unique (treat IP as System.Version for stable ordering)
$allIPs = $allIPs | Sort-Object -Unique -Property { [System.Version]$_ }

if ($ranges.Count -gt 0) {
  Write-Host "`nExpanded Ranges:"
  foreach ($r in $ranges) {
    Write-Host "  $($r.CIDR) => $($r.Range) ($($r.Count) IPs)"
  }
}
Write-Host "Total unique IPs: $($allIPs.Count)`n" -ForegroundColor Cyan

# ===== Ports =====
Write-Host "Parsing port list..." -ForegroundColor Cyan
$allPorts = Expand-PortList $Ports | Sort-Object -Unique

# ===== Optional Ping (parallel), DOES NOT gate scans =====
$PingRecords = @()
if ($Ping) {
  Write-Host "Pinging hosts (successes only will be printed)..." -ForegroundColor Cyan
  if ($psMajor -ge 7) {
    $PingRecords = $allIPs | ForEach-Object -Parallel {
      $ip = $_
      $succ = Test-Connection -TargetName $ip -Count 1 -Quiet -TimeoutSeconds 1
      $ts   = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
      [PSCustomObject]@{
        Type      = 'Ping'
        Host      = $ip
        Status    = if ($succ) { 'SUCCESS' } else { 'FAIL' }
        Timestamp = $ts
      }
    } -ThrottleLimit 32
  }
  else {
    $pool = [runspacefactory]::CreateRunspacePool(1,32); $pool.Open()
    $jobs = @()
    foreach ($ip in $allIPs) {
      $ps = [powershell]::Create().AddScript({
        param($h)
        $ping  = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($h, 250)
        $succ  = ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
        $ts    = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
        [PSCustomObject]@{
          Type      = 'Ping'
          Host      = $h
          Status    = if ($succ) { 'SUCCESS' } else { 'FAIL' }
          Timestamp = $ts
        }
      }).AddArgument($ip)
      $ps.RunspacePool = $pool
      $jobs += [PSCustomObject]@{ PS = $ps; Async = $ps.BeginInvoke() }
    }
    $PingRecords = foreach ($j in $jobs) { $r = $j.PS.EndInvoke($j.Async); $j.PS.Dispose(); $r }
    $pool.Close()
  }

  # Console: print ONLY successful pings
  foreach ($rec in $PingRecords | Where-Object { $_.Status -eq 'SUCCESS' }) {
    Write-Host " [OK]  $($rec.Host)" -ForegroundColor Green
  }
}
else {
  Write-Host "Skipping ping; proceeding directly to port scans." -ForegroundColor Yellow
}

# ===== Port Scans (parallel) =====
Write-Host "`nStarting port scans..." -ForegroundColor Cyan
$PortRecords = @()

if ($psMajor -ge 7) {
  $PortRecords = $allIPs | ForEach-Object -Parallel {
    param($ports)
    $ipAddr = $_
    foreach ($port in $ports) {
      $c = [System.Net.Sockets.TcpClient]::new()
      $c.ReceiveTimeout = 250; $c.SendTimeout = 250
      $ok = $c.ConnectAsync($ipAddr, $port).Wait(250)
      $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
      $c.Close()
      [PSCustomObject]@{
        Type      = 'Port'
        Host      = $ipAddr
        Port      = $port
        Status    = if ($ok) { 'OPEN' } else { 'CLOSED' }
        Timestamp = $ts
      }
    }
  } -ArgumentList ($allPorts) -ThrottleLimit 16
}
else {
  $pool = [runspacefactory]::CreateRunspacePool(1,16); $pool.Open()
  $jobs = @()
  foreach ($ipTarget in $allIPs) {
    foreach ($port in $allPorts) {
      $ps = [powershell]::Create().AddScript({
        param($h,$p)
        $c = [System.Net.Sockets.TcpClient]::new()
        $c.ReceiveTimeout = 250; $c.SendTimeout = 250
        $ok = $c.ConnectAsync($h,$p).Wait(250)
        $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
        $c.Close()
        [PSCustomObject]@{
          Type      = 'Port'
          Host      = $h
          Port      = $p
          Status    = if ($ok) { 'OPEN' } else { 'CLOSED' }
          Timestamp = $ts
        }
      }).AddArgument($ipTarget).AddArgument($port)
      $ps.RunspacePool = $pool
      $jobs += [PSCustomObject]@{ PS = $ps; Async = $ps.BeginInvoke() }
    }
  }
  $PortRecords = foreach ($j in $jobs) { $r = $j.PS.EndInvoke($j.Async); $j.PS.Dispose(); $r }
  $pool.Close()
}

# ===== Console output (only successes) =====
# Print only hosts with at least one OPEN port
$PortRecords | Where-Object { $_.Status -eq 'OPEN' } | Group-Object Host | ForEach-Object {
  $name = $_.Name
  $opens = $_.Group | Where-Object { $_.Status -eq 'OPEN' }
  if ($opens.Count -gt 0) {
    Write-Host "`n=== Results for $name ===" -ForegroundColor Yellow
    foreach ($rec in $opens) {
      Write-Host "  [OPEN] $($name):$($rec.Port)" -ForegroundColor Green
    }
  }
}

# ===== Export results in requested format =====
$includeFailures = ($VerbosePreference -eq 'Continue')  # include closed ports / failed pings only with -Verbose
$OutputPathFinal = Ensure-OutputPath -Path $OutputFile -AsJson:$Json
Export-Results -PingRecords $PingRecords -PortRecords $PortRecords -OutputPath $OutputPathFinal -AsJson:$Json -IncludeFailures:$includeFailures

Write-Host "`nScan complete." -ForegroundColor Cyan
