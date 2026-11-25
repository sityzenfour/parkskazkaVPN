[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')]
    [string]$SshUser,
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $scriptDirectory 'admin.local.json'
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw 'Create admin.local.json from admin.example.json and fill in your verified server settings.'
}
$settings = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$serverAddress = [string]$settings.ServerAddress
$panelPort = [int]$settings.PanelPort
$localPort = [int]$settings.LocalPort
$loopback = '127.0.0.1'
$serverFingerprint = [string]$settings.ServerFingerprint
$panelUri = [Uri]$settings.PanelUrl
if ($serverAddress -notmatch '^[a-zA-Z0-9.-]+$' -or
    $panelPort -lt 1 -or $panelPort -gt 65535 -or
    $localPort -lt 1 -or $localPort -gt 65535) {
    throw 'Invalid server address or TCP port in admin.local.json.'
}
if ($serverFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}=?$') {
    throw 'Set the verified ED25519 server fingerprint in admin.local.json.'
}
if ($panelUri.Scheme -ne 'https' -or $panelUri.Host -ne $serverAddress -or
    $panelUri.Port -ne $panelPort -or $panelUri.UserInfo -or $panelUri.Fragment) {
    throw 'PanelUrl must be an HTTPS URL for ServerAddress and PanelPort without embedded credentials.'
}
$panelUrl = $panelUri.AbsoluteUri

$sshClient = Get-Command ssh.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $sshClient) {
    throw 'Windows OpenSSH Client не найден.'
}

$chrome = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA) |
    Where-Object { $_ } |
    ForEach-Object { Join-Path $_ 'Google\Chrome\Application\chrome.exe' } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
if (-not $chrome) {
    throw 'Google Chrome не найден.'
}

$listenerPattern = '^\s*TCP\s+(?:127\.0\.0\.1|0\.0\.0\.0):{0}\s+0\.0\.0\.0:0\s+\S+\s+(\d+)\s*$' -f $localPort
function Get-TunnelPortOwner {
    foreach ($connection in (netstat.exe -ano -p tcp)) {
        if ($connection -match $listenerPattern) {
            [int]$Matches[1]
        }
    }
}

if (Get-TunnelPortOwner) {
    throw "Локальный порт $localPort занят. Если туннель уже запущен, используй открытое окно Chrome для 3x-ui."
}

$forward = '{0}:{1}:{0}:{2}' -f $loopback, $localPort, $panelPort
$destination = "$SshUser@$serverAddress"
$logDirectory = Join-Path $env:LOCALAPPDATA '3xui-admin-tunnel'
[void][IO.Directory]::CreateDirectory($logDirectory)
$logPath = Join-Path $logDirectory ('ssh-' + [Guid]::NewGuid().ToString('N') + '.log')
$sshArguments = "-v -E `"$logPath`" -NT -o ExitOnForwardFailure=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -o StrictHostKeyChecking=ask -o HostKeyAlgorithms=ssh-ed25519 -L $forward $destination"

Write-Host 'В отдельном окне SSH введи парольную фразу ключа, если он её запросит.'
Write-Host "При первом подключении сверь отпечаток сервера: $serverFingerprint"
Write-Host "Журнал SSH: $logPath"
$tunnel = Start-Process -FilePath $sshClient.Path -ArgumentList $sshArguments -WindowStyle Normal -PassThru
$chromeStarted = $false
try {
    $deadline = (Get-Date).AddSeconds(90)
    do {
        if ($tunnel.HasExited) {
            if (Test-Path -LiteralPath $logPath) {
                Get-Content -LiteralPath $logPath -Tail 15 | ForEach-Object { Write-Host $_ }
            }
            throw "SSH завершился с кодом $($tunnel.ExitCode). Причина указана выше. Полный журнал: $logPath"
        }
        $listener = (Get-TunnelPortOwner) -contains $tunnel.Id
        if ($listener) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if (-not $listener) {
        if (Test-Path -LiteralPath $logPath) {
            Get-Content -LiteralPath $logPath -Tail 15 | ForEach-Object { Write-Host $_ }
        }
        throw "За 90 секунд SSH не открыл локальный порт. Журнал: $logPath"
    }

    $chromeProfile = Join-Path $env:LOCALAPPDATA '3xui-admin-tunnel'
    $chromeArguments = '"--user-data-dir={0}" --no-first-run --no-proxy-server "--host-resolver-rules=MAP {1}:{2} {3}:{4}" "{5}"' -f
        $chromeProfile, $serverAddress, $panelPort, $loopback, $localPort, $panelUrl
    Start-Process -FilePath $chrome -ArgumentList $chromeArguments -WindowStyle Normal
    $chromeStarted = $true
    Write-Host 'Рабочее окно Chrome открыто. Оставь окно SSH открытым, пока работаешь в панели.'
} finally {
    if (-not $chromeStarted -and -not $tunnel.HasExited) {
        Stop-Process -InputObject $tunnel -ErrorAction SilentlyContinue
    }
}
