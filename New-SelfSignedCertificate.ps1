$TenantName        = "contoso.onmicrosoft.com"
$CerOutputPath     = ".\$($TenantName)_AzureADPowerShellGraphAPICert.cer"
$StoreLocation     = "Cert:\CurrentUser\My"
$ExpirationDate    = (Get-Date).AddYears(2)
$CreateCertificateSplat = @{
    FriendlyName      = "AzureApp_InactiveUsers"
    DnsName           = $TenantName
    CertStoreLocation = $StoreLocation
    NotAfter          = $ExpirationDate
    KeyExportPolicy   = "Exportable"
    KeySpec           = "Signature"
    Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    HashAlgorithm     = "SHA256"
}
$Certificate = New-SelfSignedCertificate @CreateCertificateSplat
$CertificatePath = Join-Path -Path $StoreLocation -ChildPath $Certificate.Thumbprint
Export-Certificate -Cert $CertificatePath -FilePath $CerOutputPath | Out-Null