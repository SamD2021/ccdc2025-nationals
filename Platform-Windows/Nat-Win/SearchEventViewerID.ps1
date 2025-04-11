Get-WinEvent -LogName Security | Where-Object {
    $_.Id -eq 4625
} | Format-Table TimeCreated, Message -AutoSize
#This is finding failed logons