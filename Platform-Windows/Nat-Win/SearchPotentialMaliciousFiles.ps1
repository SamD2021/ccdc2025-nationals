Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match 'Hidden' -and $_.Extension -match '\\.(exe|ps1|bat)' }