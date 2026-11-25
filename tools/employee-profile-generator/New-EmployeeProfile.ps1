[CmdletBinding()]
param(
    [string]$Name,
    [string]$SourceFile,
    [string]$OutputDirectory,
    [string]$XrayPath
)

$ErrorActionPreference = 'Stop'
$generatorDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($generatorDirectory)) {
    $generatorDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $generatorDirectory 'profiles'
}

function ConvertFrom-VlessLink {
    param([string]$Link)

    try { $uri = [Uri]$Link } catch { throw 'Invalid VLESS link.' }
    if ($uri.Scheme -ne 'vless' -or !$uri.Host -or $uri.Port -lt 1) {
        throw 'Copy one complete VLESS link from 3x-ui.'
    }
    $clientId = [Uri]::UnescapeDataString($uri.UserInfo)
    $parsedId = [Guid]::Empty
    if (![Guid]::TryParse($clientId, [ref]$parsedId)) {
        throw 'The link must contain an employee UUID.'
    }

    $query = @{}
    foreach ($part in $uri.Query.TrimStart('?').Split('&')) {
        if (!$part) { continue }
        $pair = $part -split '=', 2
        if ($pair.Count -ne 2) { throw 'Malformed link parameter.' }
        $key = [Uri]::UnescapeDataString($pair[0])
        if ($query.ContainsKey($key)) { throw 'Duplicate link parameter.' }
        $query[$key] = [Uri]::UnescapeDataString($pair[1])
    }
    $supported = @('type','security','encryption','sni','fp','pbk','sid','spx',
        'path','host','mode','extra','flow','alpn','pqv','support-x25519mlkem768',
        'x_padding_bytes','xPaddingBytes','scMaxEachPostBytes','scMinPostsIntervalMs','uplinkChunkSize')
    foreach ($key in $query.Keys) {
        if ($key -notin $supported) {
            throw "Unsupported link parameter '$key'. Use a full JSON export as input."
        }
    }
    if ($query.type -ne 'xhttp' -or $query.security -ne 'reality') {
        throw 'This generator supports VLESS + XHTTP + REALITY links. For other transports use a full JSON export.'
    }
    if ($query.encryption -and $query.encryption -ne 'none') {
        throw 'Use a full JSON export for VLESS encryption.'
    }
    if (!$query.pbk -or !$query.sni -or !$query.fp) {
        throw 'The REALITY link must contain pbk, sni and fp.'
    }
    # This share-link flag is a compatibility hint for Mihomo. Xray uses the
    # selected uTLS fingerprint and has no matching realitySettings JSON field.
    if ($query.ContainsKey('support-x25519mlkem768') -and $query['support-x25519mlkem768'] -notin @('true','false','1','0')) {
        throw 'Invalid support-x25519mlkem768 flag in the link.'
    }
    $reality = [ordered]@{
        serverName = $query.sni
        fingerprint = $query.fp
        publicKey = $query.pbk
        shortId = [string]$query.sid
    }
    if ($query.spx) { $reality.spiderX = $query.spx }
    if ($query.pqv) { $reality.mldsa65Verify = $query.pqv }
    if ($query.alpn) { $reality.alpn = @($query.alpn.Split(',')) }
    $xhttp = [ordered]@{ path = '/'; host = [string]$query.host }
    if ($query.path) { $xhttp.path = $query.path }
    if ($query.mode) { $xhttp.mode = $query.mode }
    $extra = [pscustomobject]@{}
    if ($query.extra) {
        try { $extra = ConvertFrom-Json -InputObject $query.extra } catch {
            throw 'Invalid XHTTP extra JSON in the link.'
        }
        if ($null -eq $extra -or $extra -is [Array] -or $extra -isnot [pscustomobject]) {
            throw 'XHTTP extra must be a JSON object.'
        }
    }
    # 3x-ui emits the legacy padding parameter alongside extra. Match its
    # importer precedence: extra overrides the legacy field, camelCase wins last.
    if ($query.x_padding_bytes -and !$extra.PSObject.Properties['xPaddingBytes']) {
        $extra | Add-Member -NotePropertyName xPaddingBytes -NotePropertyValue $query.x_padding_bytes
    }
    foreach ($field in @('xPaddingBytes','scMaxEachPostBytes','scMinPostsIntervalMs','uplinkChunkSize')) {
        if ($query[$field]) {
            $extra | Add-Member -NotePropertyName $field -NotePropertyValue $query[$field] -Force
        }
    }
    if (!$query.mode -and $extra.mode) { $xhttp.mode = $extra.mode }
    if (@($extra.PSObject.Properties).Count -gt 0) { $xhttp.extra = $extra }
    $user = [ordered]@{ id = $clientId; encryption = 'none' }
    if ($query.flow) { $user.flow = $query.flow }
    return [pscustomobject]@{
        tag = 'proxy'
        protocol = 'vless'
        settings = @{ vnext = @(@{ address = $uri.DnsSafeHost.Trim('[',']'); port = $uri.Port; users = @($user) }) }
        streamSettings = @{ network = 'xhttp'; security = 'reality'; realitySettings = $reality; xhttpSettings = $xhttp }
    }
}

try {
    Write-Host 'ParkSkazka generator 2026-11-25.5'
    if (!$Name) { $Name = Read-Host 'Employee name (example name)' }
    if ($Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$' -or $Name.EndsWith('.')) {
        throw 'Use 1-80 Latin letters, numbers, dots, underscores or hyphens for the name.'
    }
    if ($SourceFile) {
        $source = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $SourceFile).Path).Trim()
    } else {
        $source = ''
        try { $source = [string](Get-Clipboard -Raw -ErrorAction Stop) } catch {
            Write-Host 'Could not read text from the clipboard.'
        }
        $source = $source.Trim()
        if (!$source.StartsWith('vless://', [StringComparison]::OrdinalIgnoreCase) -and !$source.StartsWith('{')) {
            Write-Host 'The clipboard has no VLESS link or full JSON configuration.'
            $source = [string](Read-Host 'Paste the employee VLESS link here and press Enter')
            $source = $source.Trim()
        }
    }
    $source = $source -replace '^vless\\://', 'vless://'
    if (!$source) { throw 'No profile was provided. Copy a VLESS link from 3x-ui and run Create-Profile.cmd again.' }
    if ($source.StartsWith('vless://', [StringComparison]::OrdinalIgnoreCase)) {
        if ($source -match '[\r\n]') { throw 'Copy exactly one employee link.' }
        Write-Host 'VLESS link found. Generating the employee profile.'
        $proxy = ConvertFrom-VlessLink $source
    } else {
        try { $inputConfig = ConvertFrom-Json -InputObject $source } catch {
            throw 'Input must be one VLESS link or one complete Xray JSON client configuration.'
        }
        if ($inputConfig -is [Array]) { throw 'Select one client, not a subscription array.' }
        $candidates = @($inputConfig.outbounds | Where-Object { $_.tag -eq 'proxy' -and $_.protocol -eq 'vless' })
        if ($candidates.Count -ne 1) { throw 'Expected one VLESS outbound with tag proxy.' }
        $proxy = $candidates[0]
        if ($proxy.proxySettings -or $proxy.streamSettings.sockopt.dialerProxy) {
            throw 'Chained outbounds require a separate template.'
        }
    }
    $templatePath = Join-Path $generatorDirectory 'employee-template.json'
    $config = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($templatePath))
    $config.outbounds = @($proxy) + @($config.outbounds)
    $json = ConvertTo-Json -InputObject $config -Depth 80
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    [void][IO.Directory]::CreateDirectory($outputRoot)
    $outputPath = Join-Path $outputRoot ($Name + '.json')
    if (Test-Path -LiteralPath $outputPath) { throw 'This employee file already exists. Choose a new name or move the existing file.' }

    $temporaryPath = Join-Path $outputRoot ([Guid]::NewGuid().ToString('N') + '.tmp.json')
    try {
        [IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        if (!$XrayPath) {
            $installedXray = Join-Path $env:USERPROFILE 'Desktop\v2rayN-windows-64\bin\xray\xray.exe'
            $bundledXray = Join-Path $generatorDirectory 'xray\xray.exe'
            if (Test-Path -LiteralPath $bundledXray) { $XrayPath = $bundledXray }
            elseif (Test-Path -LiteralPath $installedXray) { $XrayPath = $installedXray }
        }
        if ($XrayPath) {
            $previousAssets = $env:XRAY_LOCATION_ASSET
            try {
                $xrayDirectory = Split-Path -Parent (Resolve-Path -LiteralPath $XrayPath).Path
                $assetRoots = @($xrayDirectory, (Join-Path $xrayDirectory '..\..'), (Join-Path $xrayDirectory '..\..\binConfigs'))
                foreach ($assetRoot in $assetRoots) {
                    $asset = Get-ChildItem -LiteralPath $assetRoot -Filter geoip.dat -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($asset) { $env:XRAY_LOCATION_ASSET = $asset.DirectoryName; break }
                }
                $validation = & $XrayPath run -test -config $temporaryPath 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'Xray rejected the generated configuration. Check input settings and geoip/geosite assets.' }
                Write-Host 'Xray configuration check passed.'
            } finally { $env:XRAY_LOCATION_ASSET = $previousAssets }
        } else {
            Write-Host 'Xray executable was not found. JSON was generated without an Xray configuration check.'
        }
        # Move without overwrite also protects against concurrent generation of the same name.
        [IO.File]::Move($temporaryPath, $outputPath)
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath }
    }
    Write-Host "Created $outputPath"
} catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 1
}
