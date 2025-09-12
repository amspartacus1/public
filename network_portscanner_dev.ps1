<#
.SYNOPSIS
    Ping and TCP-port scan a list of IPs/ranges concurrently, then print results to the terminal and optionally save to a file,
    using runspaces on PowerShell 5.1 or ForEach-Object -Parallel on PowerShell 7+.

.PARAMETER IPs
    Comma-separated IPs or CIDR ranges (e.g. "192.168.1.0/24,10.0.0.5")

.PARAMETER Ports
    Comma-separated TCP ports or port ranges (e.g. "80,443-445,8080") — must be quoted

.PARAMETER OutputFile
    Optional path to save results

.PARAMETER Ping
    Switch: if present, hosts will be pinged (statuses printed), but ports are scanned regardless
#>

param(
    [Parameter(Mandatory=$true, Position=0)] [string] $IPs,
    [Parameter(Mandatory=$true, Position=1)] [string] $Ports,
    [Parameter(Mandatory=$false, Position=2)] [string] $OutputFile,
    [switch] $Ping
)

# Version check
$psVersion = $PSVersionTable.PSVersion
$psMajor   = $psVersion.Major
Write-Host "Detected PowerShell version $psVersion" -ForegroundColor Cyan

# Pre-compile regex for speed
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
            $start, $end = [int]$m.Groups[1].Value, [int]$m.Groups[2].Value
            for ($i = $start; $i -le $end; $i++) { $i }
        }
        elseif ($singlePortRegex.IsMatch($p)) {
            [int]$p
        }
        else {
            Write-Warning "Skipping invalid port entry: '$p'"
        }
    }
}

function Get-IPRangeFromCIDR {
    param([string]$cidr)
    $parts = $cidr.Split('/')
    if ($parts.Count -ne 2) { throw "Invalid CIDR: $cidr" }
    $ipString, $prefixLength = $parts[0], [int]$parts[1]
    if ($prefixLength -lt 0 -or $prefixLength -gt 32) { throw "Invalid prefix in $cidr" }

    # Convert IP to uint32
    $bytes  = [System.Net.IPAddress]::Parse($ipString).GetAddressBytes()
    [Array]::Reverse($bytes)
    $ipUint = [BitConverter]::ToUInt32($bytes,0)

    # Build mask safely
    if ($prefixLength -eq 0) {
        $mask = [uint32]0
    }
    elseif ($prefixLength -eq 32) {
        $mask = [uint32]0xFFFFFFFF
    }
    else {
        $shift = 32 - $prefixLength
        $mask  = [uint32](
            (([uint64]4294967295) -shl $shift) -band 4294967295
        )
    }

    $network   = $ipUint -band $mask
    $hostCount = [uint32]((-bnot $mask) -band 0xFFFFFFFF)
    $broadcast = if ($prefixLength -eq 32) { $network }
                 elseif ($prefixLength -eq 0)  { [uint32]0xFFFFFFFF }
                 else                          { $network + $hostCount }

    for ($addr = $network; $addr -le $broadcast; $addr++) {
        $b = [BitConverter]::GetBytes([uint32]$addr)
        [Array]::Reverse($b)
        [System.Net.IPAddress]::new($b).ToString()
    }
}

# Expand and dedupe IPs
Write-Host "Expanding IP list..." -ForegroundColor Cyan
$allIPs = @(); $ranges = @()
foreach ($e in $IPs.Split(',')) {
    $v = $e.Trim()
    if ($cidrRegex.IsMatch($v)) {
        Write-Host "  CIDR $v"
        $exp = @(Get-IPRangeFromCIDR $v)
        $ranges += [PSCustomObject]@{
            CIDR  = $v
            Range = "$($exp[0])-$($exp[-1])"
            Count = $exp.Count
        }
        $allIPs += $exp
    }
    elseif ($ipRegex.IsMatch($v)) {
        $allIPs += $v
    }
    else {
        Write-Warning "Invalid IP/CIDR: $v"
    }
}
$allIPs = $allIPs | Sort-Object -Unique -Property { [System.Version]$_ }

# Show range info
Write-Host "`nExpanded Ranges:"
foreach ($r in $ranges) {
    Write-Host "  $($r.CIDR) => $($r.Range) ($($r.Count) IPs)"
}
Write-Host "Total unique IPs: $($allIPs.Count)`n" -ForegroundColor Cyan

# Parse ports
Write-Host "Parsing port list..." -ForegroundColor Cyan
$allPorts = Expand-PortList $Ports | Sort-Object -Unique

# Prepare output file
if ($OutputFile) {
    Write-Host "Logging to $OutputFile" -ForegroundColor Cyan
    "Scan Results - $(Get-Date -Format u)" | Out-File $OutputFile
}

# Ping statuses (does not filter)
if ($Ping) {
    Write-Host "Pinging hosts (statuses only)..." -ForegroundColor Cyan
    foreach ($ipAddress in $allIPs) {
        Write-Host " Pinging $ipAddress..." -NoNewline
        if (Test-Connection -Count 1 -Quiet $ipAddress) {
            Write-Host " OK" -ForegroundColor Green
        } else {
            Write-Host " FAIL" -ForegroundColor Red
        }
    }
} else {
    Write-Host "Skipping ping; proceeding to port scans." -ForegroundColor Yellow
}

# Always scan all IPs
$reachable = $allIPs

Write-Host "`nStarting port scans..." -ForegroundColor Cyan

if ($psMajor -ge 7) {
    # PowerShell 7+: parallel
    $scanResults = $reachable | ForEach-Object -Parallel {
        param($ports)
        $ipAddr = $_
        foreach ($portArg in $ports) {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.ReceiveTimeout = 250; $c.SendTimeout = 250
            $ok = $c.ConnectAsync($ipAddr, $portArg).Wait(250)
            $c.Close()
            $status = if ($ok) { 'OPEN' } else { 'CLOSED' }
            [PSCustomObject]@{
                Host   = $ipAddr
                Port   = $portArg
                Status = $status
            }
        }
    } -ArgumentList ($allPorts) -ThrottleLimit 16
}
else {
    # PowerShell 5.1: runspace pool
    $pool = [runspacefactory]::CreateRunspacePool(1,16)
    $pool.Open()
    $jobs = @()
    foreach ($target in $reachable) {
        foreach ($portArg in $allPorts) {
            $ps = [powershell]::Create().AddScript({
                param($ipA,$pA)
                $c = [System.Net.Sockets.TcpClient]::new()
                $c.ReceiveTimeout = 250; $c.SendTimeout = 250
                $ok = $c.ConnectAsync($ipA,$pA).Wait(250)
                $c.Close()
                $status = if ($ok) { 'OPEN' } else { 'CLOSED' }
                [PSCustomObject]@{
                    Host   = $ipA
                    Port   = $pA
                    Status = $status
                }
            }).AddArgument($target).AddArgument($portArg)
            $ps.RunspacePool = $pool
            $async = $ps.BeginInvoke()
            $jobs += [PSCustomObject]@{ PS = $ps; Async = $async }
        }
    }
    $scanResults = foreach ($j in $jobs) {
        $r = $j.PS.EndInvoke($j.Async)
        $j.PS.Dispose()
        $r
    }
    $pool.Close()
}

# Output results grouped by host
$scanResults | Group-Object Host | ForEach-Object {
    $ipName = $_.Name
    Write-Host "`n=== Results for $ipName ===" -ForegroundColor Yellow
    if ($OutputFile) { "`n=== Results for $ipName ===" | Out-File $OutputFile -Append }
    $_.Group | ForEach-Object {
        $tag   = if ($_.Status -eq 'OPEN') { '[OPEN]   ' } else { '[CLOSED] ' }
        $color = if ($_.Status -eq 'OPEN') { 'Green' } else { 'Red' }
        Write-Host "  $tag$($ipName):$($_.Port)" -ForegroundColor $color
        if ($OutputFile) { "  $($_.Port) : $($_.Status)" | Out-File $OutputFile -Append }
    }
}

Write-Host "`nScan complete." -ForegroundColor Cyan
if ($OutputFile) {
    Write-Host "Results saved to $OutputFile" -ForegroundColor Cyan
}
