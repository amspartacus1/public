<#
.SYNOPSIS
  Stream-friendly ping + TCP port scanner with CSV (default) or JSON output, with optional progress indicators.

.PARAMETER IPs
  Comma-separated IPs/CIDRs OR path to a text file (one IP/CIDR per line; '#' comments allowed).

.PARAMETER Ports
  Comma-separated TCP ports/ranges (e.g. "80,443-445,8080").

.PARAMETER OutputFile
  Optional path. If no .csv/.json extension, it's appended based on -Json.

.PARAMETER Json
  If set, export JSON (grouped by IP). Otherwise CSV (flat) is used.

.PARAMETER Ping
  If set, ping hosts in parallel (does not gate scans).

.PARAMETER TimeoutMs
  Per-port TCP connect timeout in milliseconds (default 250).

.PARAMETER ThrottleLimit
  Max parallel scans per chunk (default 16).

.PARAMETER PingThrottle
  Max parallel pings per chunk (default 32).

.PARAMETER ChunkSize
  Number of IPs per chunk to process in parallel (default 4096).

.PARAMETER ShowProgress
  Show progress bars and rates during ping/scan.

.PARAMETER EstimateTotal
  Do a fast pre-count of total IPs to enable percent complete and ETA (adds a streaming pass).
#>

param(
  [Parameter(Mandatory=$true, Position=0)]
  [string] $IPs,

  [Parameter(Mandatory=$true, Position=1)]
  [string] $Ports,

  [Parameter(Mandatory=$false, Position=2)]
  [string] $OutputFile,

  [switch] $Json,
  [switch] $Ping,

  [int] $TimeoutMs = 250,
  [int] $ThrottleLimit = 16,
  [int] $PingThrottle = 32,
  [int] $ChunkSize = 4096,

  [switch] $ShowProgress,
  [switch] $EstimateTotal
)

# ===== Version check =====
$psVersion = $PSVersionTable.PSVersion
$psMajor   = $psVersion.Major
Write-Host "Detected PowerShell version $psVersion" -ForegroundColor Cyan

# ===== Fast IP helpers =====
function Convert-IPToUInt32 {
  param([Parameter(Mandatory)][string]$Ip)
  $parts = $Ip.Split('.')
  if ($parts.Count -ne 4) { return $null }
  try {
    $n0 = [byte]$parts[0]; $n1 = [byte]$parts[1]; $n2 = [byte]$parts[2]; $n3 = [byte]$parts[3]
    return ([uint32]$n0 -shl 24) -bor ([uint32]$n1 -shl 16) -bor ([uint32]$n2 -shl 8) -bor [uint32]$n3
  } catch { return $null }
}

function Convert-UInt32ToIP {
  param([Parameter(Mandatory)][uint32]$Num)
  return ('{0}.{1}.{2}.{3}' -f (($Num -shr 24) -band 0xFF),
                              (($Num -shr 16) -band 0xFF),
                              (($Num -shr 8)  -band 0xFF),
                              ($Num -band 0xFF))
}

# Safe CIDR expansion using uint64 arithmetic (no -bnot / tricky shifts)
function Get-CIDRAddresses {
  param([Parameter(Mandatory)][string]$Cidr)

  $split = $Cidr.Split('/')
  if ($split.Count -ne 2) { return }
  $baseIp = $split[0]
  $prefix = [int]$split[1]
  if ($prefix -lt 0 -or $prefix -gt 32) { return }

  $baseNum32 = Convert-IPToUInt32 $baseIp
  if ($null -eq $baseNum32) { return }
  $baseNum64 = [uint64]$baseNum32

  $hostBits = 32 - $prefix

  if ($hostBits -eq 0) {
    # /32 -> single IP
    $baseIp
    return
  }

  if ($hostBits -eq 32) {
    # /0 -> entire IPv4 space (WARNING: massive). Emit lazily if present.
    for ($n64 = [uint64]0; $n64 -le [uint64]0xFFFFFFFF; $n64++) {
      Convert-UInt32ToIP ([uint32]$n64)
    }
    return
  }

  # General case
  $blockSize = [uint64]1
  $blockSize = $blockSize -shl $hostBits    # 2^(hostBits)
  $start64   = ([uint64]([math]::Floor($baseNum64 / $blockSize))) * $blockSize
  $end64     = $start64 + $blockSize - 1

  for ($n64 = $start64; $n64 -le $end64; $n64++) {
    Convert-UInt32ToIP ([uint32]$n64)
  }
}

# ===== Ports parser =====
$rangeRegex      = [regex]'^\s*(\d+)\s*-\s*(\d+)\s*$'
$singlePortRegex = [regex]'^\s*\d+\s*$'
function Expand-PortList {
  param([string]$portString)
  foreach ($p in $portString.Split(',')) {
    $pTrim = $p.Trim()
    if ($rangeRegex.IsMatch($pTrim)) {
      $m = $rangeRegex.Match($pTrim)
      $start = [int]$m.Groups[1].Value
      $end   = [int]$m.Groups[2].Value
      for ($i=$start; $i -le $end; $i++) { $i }
    }
    elseif ($singlePortRegex.IsMatch($pTrim)) { [int]$pTrim }
    else { Write-Warning "Skipping invalid port entry: '$pTrim'" }
  }
}
$allPorts = Expand-PortList $Ports | Sort-Object -Unique

# ===== Streaming input + HashSet dedupe =====
function Get-InputIPsStream {
  param([Parameter(Mandatory)][string]$IPsInput)
  $seen = [System.Collections.Generic.HashSet[uint32]]::new()

  if (Test-Path -LiteralPath $IPsInput) {
    Write-Host "Reading IPs from file (streaming): $IPsInput" -ForegroundColor Yellow
    Get-Content -LiteralPath $IPsInput -ReadCount 20000 | ForEach-Object {
      foreach ($line in $_) {
        if (-not $line) { continue }
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t[0] -eq '#') { continue }

        foreach ($seg in $t.Split(',')) {
          $s = $seg.Trim()
          if ($s.Length -eq 0) { continue }

          if ($s.Contains('/')) {
            foreach ($ip in Get-CIDRAddresses -Cidr $s) {
              $n = Convert-IPToUInt32 $ip
              if ($null -ne $n -and $seen.Add($n)) { $ip }
            }
          } else {
            $n = Convert-IPToUInt32 $s
            if ($null -ne $n -and $seen.Add($n)) { $s }
          }
        }
      }
    }
  }
  else {
    foreach ($seg in $IPsInput.Split(',')) {
      $s = $seg.Trim()
      if ($s.Length -eq 0) { continue }

      if ($s.Contains('/')) {
        foreach ($ip in Get-CIDRAddresses -Cidr $s) {
          $n = Convert-IPToUInt32 $ip
          if ($null -ne $n -and $seen.Add($n)) { $ip }
        }
      } else {
        $n = Convert-IPToUInt32 $s
        if ($null -ne $n -and $seen.Add($n)) { $s }
      }
    }
  }
}

# ===== Output helpers =====
function Ensure-OutputPath {
  param([string] $Path, [switch] $AsJson)
  if (-not $Path) { return $null }
  $ext = [System.IO.Path]::GetExtension($Path)
  $desiredExt = if ($AsJson) { '.json' } else { '.csv' }
  if ([string]::IsNullOrWhiteSpace($ext) -or ($ext.ToLower() -notin @('.csv','.json'))) {
    return "$Path$desiredExt"
  }
  return $Path
}

# JSON grouped exporter: { ip, ping[], ports[] } with epoch seconds (local clock)
function Export-GroupedJson {
  param(
    [Parameter(Mandatory)] $PingRecords,
    [Parameter(Mandatory)] $PortRecords,
    [Parameter(Mandatory)] [string] $Path,
    [switch] $IncludeFailures
  )

  $byIp = @{}

  foreach ($p in $PingRecords) {
    if (-not $IncludeFailures -and $p.Status -ne 'SUCCESS') { continue }
    if (-not $byIp.ContainsKey($p.Host)) {
      $byIp[$p.Host] = [ordered]@{ ip=$p.Host; ping=@(); ports=@() }
    }
    $pingStatus = if ($p.Status -eq 'SUCCESS') { 'success' } else { 'fail' }
    $byIp[$p.Host].ping += @{ timestamp = [string]$p.Timestamp; status = $pingStatus }
  }

  foreach ($r in $PortRecords) {
    if (-not $IncludeFailures -and $r.Status -ne 'OPEN') { continue }
    if (-not $byIp.ContainsKey($r.Host)) {
      $byIp[$r.Host] = [ordered]@{ ip=$r.Host; ping=@(); ports=@() }
    }
    $portStatus = if ($r.Status -eq 'OPEN') { 'open' } else { 'closed' }
    $byIp[$r.Host].ports += @{ port = [int]$r.Port; status = $portStatus; timestamp = [string]$r.Timestamp }
  }

  $arr = @()
  foreach ($k in ($byIp.Keys | Sort-Object { [System.Version]$_ })) { $arr += $byIp[$k] }

  # Always write a file, even if empty array
  if ($arr.Count -eq 0) { $arr = @() }

  $arr | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
  Write-Host "Results saved to $Path (format: JSON)" -ForegroundColor Cyan
}

# CSV flat exporter
function Export-CSVFlat {
  param(
    [Parameter(Mandatory)] $PingRecords,
    [Parameter(Mandatory)] $PortRecords,
    [Parameter(Mandatory)] [string] $Path,
    [switch] $IncludeFailures
  )

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

  # Always create the file; may be 0 rows if no successes and not -Verbose
  $flat | Export-Csv -LiteralPath $Path -Encoding UTF8 -NoTypeInformation
  Write-Host "Results saved to $Path ($($flat.Count) rows; format: CSV)" -ForegroundColor Cyan
}

# Epoch helper (host local time -> epoch seconds)
function Get-LocalEpoch { [int64][System.DateTimeOffset]::Now.ToUnixTimeSeconds() }

# ===== Progress helpers =====
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$progressIdPing = 1
$progressIdScan = 2
[int64]$processedPingHosts = 0
[int64]$processedPortTests = 0
[int64]$totalIPsEstimate   = 0
[int64]$totalTestsEstimate = 0

function Update-PingProgress {
  param([int]$Added)
  if (-not $ShowProgress) { return }
  $script:processedPingHosts += [int64]$Added
  $rate = 0
  if ($sw.Elapsed.TotalSeconds -gt 0) { $rate = [int]($processedPingHosts / $sw.Elapsed.TotalSeconds) }
  if ($EstimateTotal -and $totalIPsEstimate -gt 0) {
    $pct    = [int](100 * $processedPingHosts / $totalIPsEstimate)
    $remain = $totalIPsEstimate - $processedPingHosts
    $etaSec = if ($rate -gt 0) { [int]($remain / $rate) } else { 0 }
    $status = "Pinged $processedPingHosts/$totalIPsEstimate hosts @ ~${rate}/s | ETA ~ ${etaSec}s"
    Write-Progress -Id $progressIdPing -Activity "Pinging hosts" -Status $status -PercentComplete $pct
  } else {
    $status = "Pinged $processedPingHosts hosts @ ~${rate}/s"
    Write-Progress -Id $progressIdPing -Activity "Pinging hosts" -Status $status
  }
}

function Update-ScanProgress {
  param([int]$AddedHosts)
  if (-not $ShowProgress) { return }
  $addedTests = [int64]$AddedHosts * [int64]$allPorts.Count
  $script:processedPortTests += $addedTests
  $rate = 0
  if ($sw.Elapsed.TotalSeconds -gt 0) { $rate = [int]($processedPortTests / $sw.Elapsed.TotalSeconds) }
  if ($EstimateTotal -and $totalTestsEstimate -gt 0) {
    $pct    = [int](100 * $processedPortTests / $totalTestsEstimate)
    $remain = $totalTestsEstimate - $processedPortTests
    $etaSec = if ($rate -gt 0) { [int]($remain / $rate) } else { 0 }
    $status = "Tested $processedPortTests/$totalTestsEstimate ports @ ~${rate}/s | ETA ~ ${etaSec}s"
    Write-Progress -Id $progressIdScan -Activity "Scanning TCP ports" -Status $status -PercentComplete $pct
  } else {
    $status = "Tested $processedPortTests ports @ ~${rate}/s"
    Write-Progress -Id $progressIdScan -Activity "Scanning TCP ports" -Status $status
  }
}

# ====== MAIN ======
# Optional: estimate totals for percent/ETA
if ($ShowProgress -and $EstimateTotal) {
  Write-Host "Estimating totals for progress..." -ForegroundColor Yellow
  $totalIPsEstimate = 0
  foreach ($__ip in (Get-InputIPsStream -IPsInput $IPs)) { $totalIPsEstimate++ }
  $totalTestsEstimate = [int64]$totalIPsEstimate * [int64]$allPorts.Count
  Write-Host "Estimated: $totalIPsEstimate IP(s), $totalTestsEstimate port test(s)" -ForegroundColor Yellow
}

Write-Host "Expanding IP list (streaming + dedupe)..." -ForegroundColor Cyan
$ipStream = Get-InputIPsStream -IPsInput $IPs

# ---------- Optional Ping (chunked parallel) ----------
$PingRecords = @()
if ($Ping) {
  Write-Host "Pinging hosts (printing successes only)..." -ForegroundColor Cyan
  $chunk = New-Object System.Collections.Generic.List[string]
  foreach ($ip in $ipStream) {
    $null = $chunk.Add($ip)
    if ($chunk.Count -ge $ChunkSize) {
      if ($psMajor -ge 7) {
        $PingRecords += $chunk | ForEach-Object -Parallel {
          $ip = $_
          $succ = Test-Connection -TargetName $ip -Count 1 -Quiet -TimeoutSeconds 1
          $status = if ($succ) { 'SUCCESS' } else { 'FAIL' }
          $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
          [PSCustomObject]@{ Type='Ping'; Host=$ip; Status=$status; Timestamp=$ts }
        } -ThrottleLimit $PingThrottle
      } else {
        $pool = [runspacefactory]::CreateRunspacePool(1,$PingThrottle); $pool.Open()
        $jobs = @()
        foreach ($ipAddr in $chunk) {
          $ps = [powershell]::Create().AddScript({
            param($h)
            $ping  = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($h, 250)
            $succ  = ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
            $status = if ($succ) { 'SUCCESS' } else { 'FAIL' }
            $ts    = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
            [PSCustomObject]@{ Type='Ping'; Host=$h; Status=$status; Timestamp=$ts }
          }).AddArgument($ipAddr)
          $ps.RunspacePool = $pool
          $jobs += @{ PS = $ps; Async = $ps.BeginInvoke() }
        }
        foreach ($j in $jobs) { $PingRecords += $j.PS.EndInvoke($j.Async); $j.PS.Dispose() }
        $pool.Close()
      }
      Update-PingProgress -Added $chunk.Count
      $chunk.Clear()
    }
  }
  # process tail
  if ($chunk.Count -gt 0) {
    if ($psMajor -ge 7) {
      $PingRecords += $chunk | ForEach-Object -Parallel {
        $ip = $_
        $succ = Test-Connection -TargetName $ip -Count 1 -Quiet -TimeoutSeconds 1
        $status = if ($succ) { 'SUCCESS' } else { 'FAIL' }
        $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
        [PSCustomObject]@{ Type='Ping'; Host=$ip; Status=$status; Timestamp=$ts }
      } -ThrottleLimit $PingThrottle
    } else {
      $pool = [runspacefactory]::CreateRunspacePool(1,$PingThrottle); $pool.Open()
      $jobs = @()
      foreach ($ipAddr in $chunk) {
        $ps = [powershell]::Create().AddScript({
          param($h)
          $ping  = New-Object System.Net.NetworkInformation.Ping
          $reply = $ping.Send($h, 250)
          $succ  = ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
          $status = if ($succ) { 'SUCCESS' } else { 'FAIL' }
          $ts    = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
          [PSCustomObject]@{ Type='Ping'; Host=$h; Status=$status; Timestamp=$ts }
        }).AddArgument($ipAddr)
        $ps.RunspacePool = $pool
        $jobs += @{ PS = $ps; Async = $ps.BeginInvoke() }
      }
      foreach ($j in $jobs) { $PingRecords += $j.PS.EndInvoke($j.Async); $j.PS.Dispose() }
      $pool.Close()
    }
    Update-PingProgress -Added $chunk.Count
    $chunk.Clear()
  }

  # Console: ONLY successes
  foreach ($rec in $PingRecords | Where-Object { $_.Status -eq 'SUCCESS' }) {
    Write-Host " [OK]  $($rec.Host)" -ForegroundColor Green
  }

  if ($ShowProgress) { Write-Progress -Id $progressIdPing -Activity "Pinging hosts" -Completed }

  # Reset the stream for scans (re-enumerate the input)
  $ipStream = Get-InputIPsStream -IPsInput $IPs
} else {
  Write-Host "Skipping ping; proceeding directly to port scans." -ForegroundColor Yellow
}

# ---------- Port scans (chunked parallel) ----------
Write-Host "`nStarting port scans..." -ForegroundColor Cyan
$PortRecords = @()
$chunk2 = New-Object System.Collections.Generic.List[string]

foreach ($ip in $ipStream) {
  $null = $chunk2.Add($ip)
  if ($chunk2.Count -ge $ChunkSize) {
    if ($psMajor -ge 7) {
      $PortRecords += $chunk2 | ForEach-Object -Parallel {
        param($ports,$timeout)
        $ipAddr = $_
        foreach ($port in $ports) {
          $c = [System.Net.Sockets.TcpClient]::new()
          $c.ReceiveTimeout = $timeout; $c.SendTimeout = $timeout
          $ok = $c.ConnectAsync($ipAddr,$port).Wait($timeout)
          $status = if ($ok) { 'OPEN' } else { 'CLOSED' }
          $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
          $c.Dispose()
          [PSCustomObject]@{ Type='Port'; Host=$ipAddr; Port=$port; Status=$status; Timestamp=$ts }
        }
      } -ArgumentList ($allPorts,$TimeoutMs) -ThrottleLimit $ThrottleLimit
    } else {
      $pool = [runspacefactory]::CreateRunspacePool(1,$ThrottleLimit); $pool.Open()
      $jobs = @()
      foreach ($ipAddr in $chunk2) {
        foreach ($port in $allPorts) {
          $ps = [powershell]::Create().AddScript({
            param($h,$p,$timeout)
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.ReceiveTimeout = $timeout; $c.SendTimeout = $timeout
            $ok = $c.ConnectAsync($h,$p).Wait($timeout)
            $status = if ($ok) { 'OPEN' } else { 'CLOSED' }
            $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
            $c.Dispose()
            [PSCustomObject]@{ Type='Port'; Host=$h; Port=$p; Status=$status; Timestamp=$ts }
          }).AddArgument($ipAddr).AddArgument($port).AddArgument($TimeoutMs)
          $ps.RunspacePool = $pool
          $jobs += @{ PS = $ps; Async = $ps.BeginInvoke() }
        }
      }
      foreach ($j in $jobs) { $PortRecords += $j.PS.EndInvoke($j.Async); $j.PS.Dispose() }
      $pool.Close()
    }
    Update-ScanProgress -AddedHosts $chunk2.Count
    $chunk2.Clear()
  }
}

# Tail chunk
if ($chunk2.Count -gt 0) {
  if ($psMajor -ge 7) {
    $PortRecords += $chunk2 | ForEach-Object -Parallel {
      param($ports,$timeout)
      $ipAddr = $_
      foreach ($port in $ports) {
        $c = [System.Net.Sockets.TcpClient]::new()
        $c.ReceiveTimeout = $timeout; $c.SendTimeout = $timeout
        $ok = $c.ConnectAsync($ipAddr,$port).Wait($timeout)
        $status = if ($ok) { 'OPEN' } else { 'CLOSED' }
        $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
        $c.Dispose()
        [PSCustomObject]@{ Type='Port'; Host=$ipAddr; Port=$port; Status=$status; Timestamp=$ts }
      }
    } -ArgumentList ($allPorts,$TimeoutMs) -ThrottleLimit $ThrottleLimit
  } else {
    $pool = [runspacefactory]::CreateRunspacePool(1,$ThrottleLimit); $pool.Open()
    $jobs = @()
    foreach ($ipAddr in $chunk2) {
      foreach ($port in $allPorts) {
        $ps = [powershell]::Create().AddScript({
          param($h,$p,$timeout)
          $c = [System.Net.Sockets.TcpClient]::new()
          $c.ReceiveTimeout = $timeout; $c.SendTimeout = $timeout
          $ok = $c.ConnectAsync($h,$p).Wait($timeout)
          $status = if ($ok) { 'OPEN' } else { 'CLOSED' }
          $ts = [System.DateTimeOffset]::Now.ToUnixTimeSeconds()
          $c.Dispose()
          [PSCustomObject]@{ Type='Port'; Host=$h; Port=$p; Status=$status; Timestamp=$ts }
        }).AddArgument($ipAddr).AddArgument($port).AddArgument($TimeoutMs)
        $ps.RunspacePool = $pool
        $jobs += @{ PS = $ps; Async = $ps.BeginInvoke() }
      }
    }
    foreach ($j in $jobs) { $PortRecords += $j.PS.EndInvoke($j.Async); $j.PS.Dispose() }
    $pool.Close()
  }
  Update-ScanProgress -AddedHosts $chunk2.Count
  $chunk2.Clear()
}

if ($ShowProgress) { Write-Progress -Id $progressIdScan -Activity "Scanning TCP ports" -Completed }

# ----- Console output: ONLY successes -----
$PortRecords | Where-Object { $_.Status -eq 'OPEN' } | Group-Object Host | ForEach-Object {
  $name = $_.Name
  $opens = $_.Group | Where-Object { $_.Status -eq 'OPEN' }
  if ($opens.Count -gt 0) {
    Write-Host "`n=== Results for $name ===" -ForegroundColor Yellow
    foreach ($rec in $opens) { Write-Host "  [OPEN] $($name):$($rec.Port)" -ForegroundColor Green }
  }
}
if ($Ping) {
  foreach ($rec in $PingRecords | Where-Object { $_.Status -eq 'SUCCESS' }) { break }
}

# ----- Export -----
$includeFailures = ($VerbosePreference -eq 'Continue')
$finalPath = Ensure-OutputPath -Path $OutputFile -AsJson:$Json
if ($finalPath) {
  if ($Json) {
    Export-GroupedJson -PingRecords $PingRecords -PortRecords $PortRecords -Path $finalPath -IncludeFailures:$includeFailures
  } else {
    Export-CSVFlat     -PingRecords $PingRecords -PortRecords $PortRecords -Path $finalPath -IncludeFailures:$includeFailures
  }
} else {
  $fmt = if ($Json) { 'JSON' } else { 'CSV' }
  Write-Host "No output file specified. (Format preference: $fmt)" -ForegroundColor Yellow
}

Write-Host "`nScan complete." -ForegroundColor Cyan
