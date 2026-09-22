# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
param([string]$Server, [string]$Directory, [string]$Protocol)
$ErrorActionPreference = 'Stop'
$start = [Diagnostics.ProcessStartInfo]::new($Server)
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
foreach ($arg in @((Join-Path $Directory 'cert.pem'), (Join-Path $Directory 'key.pem'), (Join-Path $Directory 'ca.pem'), '2')) {
    $start.ArgumentList.Add($arg)
}
$process = [Diagnostics.Process]::Start($start)
$client = $null
$ssl = $null
try {
    if ($process.StandardOutput.ReadLine() -ne 'READY') { throw 'TLS server did not become ready' }
    $expected = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $Directory 'cert.pem'))
    try {
        $thumbprint = $expected.Thumbprint
        $client = [Net.Sockets.TcpClient]::new('127.0.0.1', 8000)
        $ssl = [Net.Security.SslStream]::new($client.GetStream(), $false,
            [Net.Security.RemoteCertificateValidationCallback]{ param($sender, $cert, $chain, $errors) return $cert.GetCertHashString() -eq $thumbprint })
        $options = [Net.Security.SslClientAuthenticationOptions]::new()
        $options.TargetHost = 'localhost'
        $options.EnabledSslProtocols = [Security.Authentication.SslProtocols]::$Protocol
        $options.ApplicationProtocols = [Collections.Generic.List[Net.Security.SslApplicationProtocol]]::new()
        $options.ApplicationProtocols.Add([Net.Security.SslApplicationProtocol]::Http2)
        $ssl.AuthenticateAsClient($options)
        if ($ssl.SslProtocol.ToString() -ne $Protocol) { throw 'Unexpected negotiated TLS version' }
        if ($ssl.NegotiatedApplicationProtocol -ne [Net.Security.SslApplicationProtocol]::Http2) { throw 'ALPN mismatch' }
        $payload = [Text.Encoding]::ASCII.GetBytes("authenticated TLS payload`0")
        # Separate writes exercise partial TLS input rather than one large record.
        foreach ($octet in $payload) { $ssl.WriteByte($octet) }
        $reply = [byte[]]::new($payload.Length)
        $offset = 0
        while ($offset -lt $reply.Length) {
            $count = $ssl.Read($reply, $offset, $reply.Length - $offset)
            if (-not $count) { throw 'Premature TLS EOF' }
            $offset += $count
        }
        if ([Convert]::ToBase64String($reply) -ne [Convert]::ToBase64String($payload)) { throw 'TLS payload mismatch' }
        if ($ssl.ReadByte() -ne -1) { throw 'Expected TLS close notification' }
        if (-not $process.WaitForExit(10000)) { throw 'TLS server did not shut down' }
        if ($process.ExitCode -ne 0) { throw "TLS server failed: $($process.ExitCode)" }
        Write-Output "$Protocol handshake, ALPN, fragmented payload, and shutdown passed"
    } finally { $expected.Dispose() }
} finally {
    if ($ssl) { $ssl.Dispose() }
    if ($client) { $client.Dispose() }
    if (-not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
    $errors = $process.StandardError.ReadToEnd()
    if ($errors) { [Console]::Error.Write($errors) }
    $process.Dispose()
}
