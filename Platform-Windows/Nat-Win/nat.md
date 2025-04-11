# National Updated Commands
- [Domain Wide Commands](#domain-wide-commands)
- [Rotate Passwords Domain Accounts](#rotate-passwords-domain-accounts)
- [Rotate Passwords Local Accounts](#local-account-password-rotation)
- [WinRM Session Command](#winrm-session-command)
- [Add Trusted Host](#add-trusted-host)
- [Enable RDP through firewall](#enable-rdp-through-firewall)
- [Enable RDP through registry](#enable-rdp-through-registry)
- [Block Outbound IP](#block-outbound-ip)
- [File Watcher](#create-a-file-watcher)
- [DNS Flush](#flush-dns)
- [Kill Malware Processes](#kill-known-malware-processes)
- [List Running Processes](#list-all-running-processes)
- [List TCP Connections](#list-all-tcp-conenctions-netstat)
- [See Recent Event Log Entries](#recent-event-log-entries)
- [See Recent Created Accounts](#recently-created-accounts)
- [Find Failed Logon Attempts](#search-failed-logon-attempts)
- [Find potential malicious files](#search-for-potential-malicious-files)
- [All Process Created Last 10 min](#all-processes-created-in-10-min)

### Domain Wide Commands
```sh
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $computers -ScriptBlock { <your command here> } -Credential (Get-Credential)
```

### Rotate Passwords Domain Accounts
**_NOTE:_** This script outputs passwords to a file
```sh
Import-Module ActiveDirectory

# List of usernames to exclude
$excludedUsers = @(
    "Administrator",       # Default domain admin
    "svc_account1",        # Example service account
    "john.doe"             # Any other account to exclude
)

# Output file for new passwords if we want it
$logFile = "C:\Users\Administrator\domain_user_passwords.csv"

# Function to generate a 20-character random password
function Generate-RandomPassword {
    param ([int]$length = 20)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $charArray = $chars.ToCharArray()
    -join ((1..$length) | ForEach-Object { Get-Random -InputObject $charArray })
}

# Get all enabled domain users
$users = Get-ADUser -Filter * -Properties SamAccountName

foreach ($user in $users) {
    if ($excludedUsers -contains $user.SamAccountName) {
        Write-Host "Skipping excluded user: $($user.SamAccountName)"
        continue
    }

    $newPassword = Generate-RandomPassword

    try {
        Set-ADUser -Identity $user.SamAccountName -PasswordNeverExpires $false
        Set-ADAccountPassword -Identity $user.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
        Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true

        "$($user.SamAccountName),$newPassword" | Out-File -FilePath $logFile -Append
        Write-Host "Updated password for $($user.SamAccountName)"
    }
    catch {
        Write-Warning "Failed to update password for $($user.SamAccountName): $_"
    }
}
```

### Local Account Password Rotation
**_NOTE:_** This script outputs passwords to a file
```sh
# List of local usernames to exclude
$excludedUsers = @(
    "Administrator",  # Default local admin
    "Guest",          # Default guest account
    "svc_local"       # Example service account
)

# Output file for new passwords
$logFile = "C:\Users\Administrator\local_user_passwords.csv"
"Username,NewPassword" | Out-File -FilePath $logFile

# Function to generate a 20-character random password
function Generate-RandomPassword {
    param ([int]$length = 20)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $charArray = $chars.ToCharArray()
    -join ((1..$length) | ForEach-Object { Get-Random -InputObject $charArray })
}

# Get all local users
$localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

foreach ($user in $localUsers) {
    if ($excludedUsers -contains $user.Name) {
        Write-Host "Skipping excluded user: $($user.Name)"
        continue
    }

    $newPassword = Generate-RandomPassword

    try {
        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        Set-LocalUser -Name $user.Name -Password $securePassword

        "$($user.Name),$newPassword" | Out-File -FilePath $logFile -Append
        Write-Host "Updated password for $($user.Name)"
    }
    catch {
        Write-Warning "Failed to update password for $($user.Name): $_"
    }
}
```

### WinRM Session Command
```sh
Enter-PSSession -ComputerName 192.168.1.100 -Credential (Get-Credential)
```

### Add Trusted Host
```sh
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.100" -Force
```

### Enable RDP through firewall
```sh
Get-NetFirewallRule -DisplayGroup "Remote Desktop"
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```
```sh
New-NetFirewallRule -DisplayName "Allow RDP Port 3389" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 3389 `
  -Action Allow `
  -Profile Domain,Private `
  -Description "Custom rule to allow RDP traffic on port 3389"
```

### Enable RDP through registry
```sh
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
```

### List all TCP conenctions (netstat)
```sh
Get-NetTCPConnection | Sort-Object State | Format-Table -AutoSize
```

### List all running processes
```sh
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = $_.State
        Process       = $proc.ProcessName
        PID           = $_.OwningProcess
    }
} | Format-Table -AutoSize
```

### Recent event log entries
```sh
Get-WinEvent -LogName Security -MaxEvents 20 | Format-List
```

### Search failed logon attempts
```sh
Get-WinEvent -LogName Security | Where-Object {
    $_.Id -eq 4625
} | Format-Table TimeCreated, Message -AutoSize
```

### Recently created accounts
```sh
Get-LocalUser | Where-Object { $_.WhenCreated -gt (Get-Date).AddHours(-1) }
```

### Kill known malware processes
```sh
$badProcs = @('mimikatz', 'procmon', 'netcat', 'nc', 'powersploit', 'metasploit')
foreach ($proc in $badProcs) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force
}
```

### Flush DNS
```sh
Clear-DnsClientCache
```

### Block outbound IP
```sh
New-NetFirewallRule -DisplayName "Block Evil IP" -Direction Outbound -RemoteAddress "123.456.789.0" -Action Block
```

### Create a file watcher
```sh
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\\Users"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent $watcher Changed -Action {
    Write-Host \"File changed: $($Event.SourceEventArgs.FullPath)\"
}
```
To unregister and stop the watcher
```sh
Unregister-Event -SubscriptionId 1
```
To get list of event IDs
```sh
Get-EventSubscriber
```

### Search for potential malicious files
```sh
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match 'Hidden' -and $_.Extension -match '\\.(exe|ps1|bat)' }
```

### All processes created in 10 min
```sh
param (
    [int]$MinutesAgo = 10  # Default to last 10 minutes
)

# Calculate the cutoff time
$cutoffTime = (Get-Date).AddMinutes(-$MinutesAgo)

# Get all processes and filter by StartTime
Get-Process | ForEach-Object {
    try {
        if ($_.StartTime -gt $cutoffTime) {
            $_
        }
    } catch {
        # Some system processes may not expose StartTime (e.g., idle/system), so we skip them
    }
}
```