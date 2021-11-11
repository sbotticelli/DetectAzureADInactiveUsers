
<br/>

# Detect AzureAD Inactive Users


<br/>
<br/>

In large environments, user accounts are not always deleted when employees leave an organization. As an IT administrator, you want to detect and handle these obsolete user accounts because they represent a security risk. This article explains a method to handle obsolete user accounts in Azure AD, using **GraphAPIs** and **Certificate Token**.

Inactive accounts are user accounts that are not required anymore by members of your organization to **gain access to your resources**. One key identifier for inactive accounts is that they haven't been used for a while to sign-in to your environment. Because inactive accounts are tied to the sign-in activity, you can use the timestamp of the last sign-in that was successful to detect them.

The challenge of this method is to define what for a while means in the case of your environment. For example, users might not sign-in to an environment for a while, because they are on vacation. When defining what your delta for inactive user accounts is, you need to factor in all legitimate reasons for not signing in to your environment. In many organizations, the delta for inactive user accounts is between 90 and 180 days.

**The last successful sign-in provides potential insights into a user's continued need for access to resources.** It can help with determining if group membership or app access is still needed or could be removed. For external user management, you can understand if an external user is still active within the tenant or should be cleaned up.

<br/>
<br/>

### Improvement:
- Use **Certificate** to request a *Token*, so you can override limits against Admin (**with MFA**) interaction and schedule

- Avoid managing **ClientID** and **ClientSecret** (even if *alternative*, **are always a Username and a Password!**)

- Use **GraphAPIs**

<br/>
<br/>

### Prerequisites:
- Create a Certificate (with [*New-SelfSignedCertificate.ps1*](https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync#new-selfsignedcertificateps1) script you can generate a Self-Signed Certificate)

- [Create](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application) an **App Registration** in Azure
  
  - [Assign](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis#application-permission-to-microsoft-graph) the following **Application Permission** :
    
    - AuditLogs.Read.All
    - Organization.Read.All

  - [Upload](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-a-certificate) the above **Certificate** to the **App Registration** in Azure 
  
- *Modify* the following variables in the [*New-SelfSignedCertificate.ps1*](https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync#new-selfsignedcertificateps1) script with your Tenant reference:
``` powershell
    $TenantName = "contoso.onmicrosoft.com"
```
- *Modify* the following variables in the [*Get-AccessTokenFromCertificate.ps1*](https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync#azureaddirectoryrolemembersyncps1) script with your Tenant, Certificate and ObjectIDs reference:
```powershell    
    $TenantId = "contoso.onmicrosoft.com"
    $AppId = ""
    $thumbprint = ""
```

<br/>
<br/>

### Code:

<br/>

#### New-SelfSignedCertificate.ps1:
```powershell
$TenantName        = "contoso.onmicrosoft.com"   #replace with your tenant information   
$CerOutputPath     = ".\$($TenantName)_AzureADPowerShellGraphAPICert.cer"
$StoreLocation     = "Cert:\CurrentUser\My"
$ExpirationDate    = (Get-Date).AddYears(2)
$CreateCertificateSplat = @{
    FriendlyName      = "AzureApp"
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
```

<br/>

#### Get-AccessTokenFromCertificate.ps1:
```powershell
$TenantId = "contoso.onmicrosoft.com"            #replace with your tenant information
$AppId = " "                                     #replace with your tenant information
$thumbprint = " "                                #replace with your tenant information

Function Get-AccessTokenFromCertificate()
{
    $Certificate = Get-Item "Cert:\CurrentUser\My\$thumbprint"
    $Scope = "https://graph.microsoft.com/.default"
    $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)
    $JWTHeader = @{
        alg = "RS256"
        typ = "JWT"
        x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
    }
    $JWTPayLoad = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        exp = $JWTExpiration
        iss = $AppId
        jti = [guid]::NewGuid()
        nbf = $NotBefore
        sub = $AppId
    }
    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)
    $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)
    $JWT = $EncodedHeader + "." + $EncodedPayload
    $PrivateKey = $Certificate.PrivateKey
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
    $Signature = [Convert]::ToBase64String(
        $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
    ) -replace '\+','-' -replace '/','_' -replace '='
    $JWT = $JWT + "." + $Signature
    $Body = @{
        client_id = $AppId
        client_assertion = $JWT
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope = $Scope
        grant_type = "client_credentials"
    }
    $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Header = @{
        Authorization = "Bearer $JWT"
    }
    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        Body = $Body
        Uri = $Url
        Headers = $Header
    }
    $global:Request = Invoke-RestMethod @PostSplat
    Write-Host $global:Request.access_token -ForegroundColor Cyan
    $global:Head = @{
        Authorization = "$($global:Request.token_type) $($global:Request.access_token)"
    }
}

Write-Host "####################### REQUESTED NEW ACCESS TOKEN ########################" -ForegroundColor DarkCyan
Get-AccessTokenFromCertificate
Write-Host "###########################################################################" -ForegroundColor DarkCyan
```

<br/>

### How to detect inactive user accounts:
You detect inactive accounts by evaluating the **lastSignInDateTime** property exposed by the signInActivity resource type of the Microsoft Graph API. The lastSignInDateTime property shows the last time a user made a successful interactive sign-in to Azure AD. Using this property, you can implement a solution for the following scenarios:

- **Users by name**: In this scenario, you search for a specific user by name, which enables you to evaluate the lastSignInDateTime: https://graph.microsoft.com/beta/users?$filter=startswith(displayName,'markvi')&$select=displayName,signInActivity

- **Users by date**: In this scenario, you request a list of users with a lastSignInDateTime before a specified date: https://graph.microsoft.com/beta/users?filter=signInActivity/lastSignInDateTime le 2019-06-01T00:00:00Z

- Report the **last sign in date of all users**: In this scenario, you request a list of all users, and the last lastSignInDateTime for each respective user: https://graph.microsoft.com/beta/users?$select=displayName,signInActivity

<br/>
<br/>

#### Example:
```powershell
$InactiveUsers = Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/users?$select=displayName,signInActivity' -Headers $global:Head -Method "GET" -ContentType "application/json"
"DisplayName,ObjectID,lastSignInDateTime,lastNonInteractiveSignInDateTime" | Out-File .\InactiveUsersReport.txt
$Users = $InactiveUsers.Value
For ($i=0; $i -lt $colors.Length; $i++) {
    "$($Users[$i].DisplayName),$($Users[$i].id),$($Users[$i].SignInActivity.lastSignInDateTime),$($Users[$i].SignInActivity.lastNonInteractiveSignInDateTime)" | Out-File .\InactiveUsersReport.txt -Append
}
```
<br/>
<br/>
<br/>
