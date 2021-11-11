$InactiveUsers = Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/users?$select=displayName,signInActivity' -Headers $global:Head -Method "GET" -ContentType "application/json"

"DisplayName,ObjectID,lastSignInDateTime,lastNonInteractiveSignInDateTime" | Out-File .\InactiveUsersReport.txt

$Users = $InactiveUsers.Value
For ($i=0; $i -lt $colors.Length; $i++) {
    "$($Users[$i].DisplayName),$($Users[$i].id),$($Users[$i].SignInActivity.lastSignInDateTime),$($Users[$i].SignInActivity.lastNonInteractiveSignInDateTime)" | Out-File .\InactiveUsersReport.txt -Append
}