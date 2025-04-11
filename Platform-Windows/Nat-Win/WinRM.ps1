Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.100" -Force
Enter-PSSession -ComputerName 192.168.1.100 -Credential (Get-Credential)