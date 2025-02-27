Import-Module ActiveDirectory

### Function to Create New Users from CSV ###
Function New-ADUsers {
    $users = Import-Csv -Path "new_users.csv"
    
    foreach ($user in $users) {
        $password = ConvertTo-SecureString $user.Password -AsPlainText -Force
        New-ADUser -Name $user.Name `
                    -GivenName $user.FirstName `
                    -Surname $user.LastName `
                    -SamAccountName $user.Username `
                    -UserPrincipalName "$($user.Username)@yourdomain.com" `
                    -Path "OU=Users,DC=yourdomain,DC=com" `
                    -AccountPassword $password `
                    -Enabled $true
        Write-Host "Created User: $($user.Username)"
    }
}

### Function to Disable Inactive Users ###
Function Disable-InactiveUsers {
    $inactiveUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) }
    
    foreach ($user in $inactiveUsers) {
        Disable-ADAccount -Identity $user.SamAccountName
        Write-Host "Disabled inactive user: $($user.SamAccountName)"
    }
}

### Function to Delete Users from CSV ###
Function Remove-ADUsers {
    $usersToDelete = Import-Csv -Path "delete_users.csv"
    
    foreach ($user in $usersToDelete) {
        Remove-ADUser -Identity $user.Username -Confirm:$false
        Write-Host "Deleted User: $($user.Username)"
    }
}

### Execute Functions ###
New-ADUsers
Disable-InactiveUsers
Remove-ADUsers

Write-Host "Active Directory User Management Automation Completed!"
