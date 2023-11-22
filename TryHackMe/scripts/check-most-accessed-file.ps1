$DaysAgo = (Get-Date).AddDays(-30)
$FileAccessEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4663
    StartTime = $DaysAgo
} | Where-Object { $_.Properties[5].Value -eq '%%4416' }

$FileAccessCount = @{}
foreach ($event in $FileAccessEvents) {
    $FileName = $event.Properties[6].Value
    if ($FileAccessCount.ContainsKey($FileName)) {
        $FileAccessCount[$FileName] += 1
    } else {
        $FileAccessCount[$FileName] = 1
    }
}

$Top20Files = $FileAccessCount.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 20
$Top20Files