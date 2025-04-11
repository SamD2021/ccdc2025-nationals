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