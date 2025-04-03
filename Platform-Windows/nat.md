# National Updated Commands
- [Domain Wide Commands](#domain-wide-commands)

### Domain Wide Commands
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $computers -ScriptBlock { <your command here> } -Credential (Get-Credential)
