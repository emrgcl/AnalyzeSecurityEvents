<#
.SYNOPSIS
    Gets the Locked Accounts on the dc and finds the source of the lockedout.
.DESCRIPTION
    Gets the Locked Accounts on the dc and finds the source of the lockedout.
.EXAMPLE
    .\Find-AccountLockingComputer.ps1 -verbose
    
    VERBOSE: [2/25/2021 10:21:38 AM] Script Started.
    VERBOSE: [2/25/2021 10:21:38 AM] Locked Account Count = 2.
    VERBOSE: [2/25/2021 10:21:38 AM] Working on testuser@contoso.com


    Name                   : testuser
    DistinguishedName      : CN=testuser,CN=Users,DC=contoso,DC=com
    UserPrincipalName      : testuser@contoso.com
    SamAccountName         : testuser
    SID                    : S-1-5-21-1615164016-501832016-2065208324-2101
    LockedOut              : True
    LockedOutCount         : 3
    LockedTime             : 2/25/2021 10:04:10 AM
    LastLockedFromComputer : emreg-dc01
    LockedFromComputers    : {emreg-dc01, emreg-web01}

    VERBOSE: [2/25/2021 10:21:40 AM] Finished Working on testuser@contoso.com . LastLockedFromComputer = emreg-dc01 ; Last LockTime = 02/25/2021 10:04:10
    VERBOSE: [2/25/2021 10:21:40 AM] Working on baduser@contoso.com
    Name                   : User
    DistinguishedName      : CN=User,CN=Users,DC=contoso,DC=com
    UserPrincipalName      : baduser@contoso.com
    SamAccountName         : baduser
    SID                    : S-1-5-21-1615164016-501832016-2065208324-43601
    LockedOut              : True
    LockedOutCount         : 3
    LockedTime             : 2/25/2021 10:04:09 AM
    LastLockedFromComputer : emreg-dc01
    LockedFromComputers    : {emreg-dc01, emreg-web01}

    VERBOSE: [2/25/2021 10:21:41 AM] Finished Working on baduser@contoso.com . LastLockedFromComputer = emreg-dc01 ; Last LockTime = 02/25/2021 10:04:09
    VERBOSE: [2/25/2021 10:21:41 AM] Script Ended.
    VERBOSE: [2/25/2021 10:21:41 AM] Script Ended.Duration: 3 seconds.

#>
[CmdLetBinding()]
Param()
#Requires -Module @{ModuleName='ActiveDirectory';ModuleVersion ='1.0.0.0'}

$ScriptStart = Get-Date
Write-Verbose -Message "[$(Get-Date -format G)] Script Started."

$LockedAccounts = Search-ADAccount -LockedOut
Write-Verbose -Message "[$(Get-Date -format G)] Locked Account Count = $($LockedAccounts.Count)."
if ($LockedAccounts) {
    Foreach ($LockedAccount in $LockedAccounts) {

    Write-Verbose -Message "[$(Get-Date -format G)] Working on $($LockedAccount.UserPrincipalName)"
    $EventLogParams = @{

    'LogName' = 'Security'
    'FilterXPath' = "*[System[EventID=4740] and EventData[Data[@Name='TargetUserName']='$($LockedAccount.SAmAccountName)']]"

    }   

    $Events = @(Get-WinEvent @EventLogPArams)
    if ($Events) {
    $LastEvent = $Events | Sort-Object -Property Timecreated -Descending | Select-Object -first 1

    [PsCustomObject]@{

        Name = $LockedAccount.Name
        DistinguishedName= $LockedAccount.DistinguishedName
        UserPrincipalName= $LockedAccount.UserPrincipalName
        SamAccountName= $LockedAccount.SamAccountName
        SID= $LockedAccount.SID
        LockedOut= $LockedAccount.LockedOut
        LockedOutCount = $Events.Count
        LockedTime = $LastEvent.TimeCreated
        LastLockedFromComputer = $LastEvent.Properties[1].Value
        LockedFromComputers = @($Events | ForEach-Object {$_.Properties[1].Value} | Select-Object -Unique)
    }

    Write-Verbose -Message "[$(Get-Date -format G)] Finished Working on $($LockedAccount.UserPrincipalName) . LastLockedFromComputer = $($LastEvent.Properties[1].Value) ; Last LockTime = $($LastEvent.TimeCreated)"

    # Insert MomSCriptApi Below if needed.
} else {

        Write-Verbose -Message "[$(Get-Date -format G)] No events found on this DC skipping."    

    }
}
} else {

    Write-Verbose "[$(Get-Date -format G)] No Acconts are locked."

}

Write-Verbose "[$(Get-Date -format G)] Script Ended."
Write-Verbose "[$(Get-Date -Format G)] Script Ended.Duration: $([Math]::Round(((Get-date)-$ScriptStart).TotalSeconds)) seconds."
