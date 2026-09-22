# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference = 'Stop'
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost')
    $san.AddIpAddress([System.Net.IPAddress]::Loopback)
    $request.CertificateExtensions.Add($san.Build())
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(1))
    try {
        [IO.File]::WriteAllText((Join-Path $Directory 'cert.pem'), $certificate.ExportCertificatePem())
        [IO.File]::WriteAllText((Join-Path $Directory 'ca.pem'), $certificate.ExportCertificatePem())
        [IO.File]::WriteAllText((Join-Path $Directory 'key.pem'), $rsa.ExportPkcs8PrivateKeyPem())
        [IO.File]::WriteAllText((Join-Path $Directory 'rsa-key.pem'), $rsa.ExportRSAPrivateKeyPem())
        $expired = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddYears(-2), [DateTimeOffset]::UtcNow.AddYears(-1))
        try { [IO.File]::WriteAllText((Join-Path $Directory 'expired.pem'), $expired.ExportCertificatePem()) }
        finally { $expired.Dispose() }
    } finally { $certificate.Dispose() }
} finally { $rsa.Dispose() }

$ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=localhost', $ec, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(1))
    try {
        [IO.File]::WriteAllText((Join-Path $Directory 'ec-cert.pem'), $certificate.ExportCertificatePem())
        [IO.File]::WriteAllText((Join-Path $Directory 'ec-key.pem'), $ec.ExportPkcs8PrivateKeyPem())
    } finally { $certificate.Dispose() }
} finally { $ec.Dispose() }
