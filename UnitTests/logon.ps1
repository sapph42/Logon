<#
.SYNOPSIS
    Consolidated logon script
.NOTES
    Name: logon.ps1
    Author: Nick Gibson
    Version: 3.4.0
    DateCreated: 19 Oct 2022
    Specifies a SQLConnection
.PARAMETER Location
    Allows alternate drive mapping
.PARAMETER UseSQL
    Allows specification at invocation if SQL logging is enabled
.INPUTS
    None. You cannot pipe objects to this script
.OUTPUTS
    None.
.CHANGELOG
    19 Oct 2022: Initial creation based on various scripts called by original logon batch file - v1.0
    19 Oct 2022: Bugfix: Account for multiple sticks of RAM
    20 Oct 2022: Added SQL functionality - v2.0
    25 Oct 2022: Added CallAlert function
    25 Oct 2022: Added HideWindow function
    25 Oct 2022: Modified PrinterLogging and ApplicationLogging to use used-defined table types to prevent dozens of INSERT queries per logon event
    26 Oct 2022: Removed all hardcoded paths and location references, moved to defined variables
    26 Oct 2022: Added switch paramters to all functions to allow turning on and off file and/or SQL logging script-wide
    26 Oct 2022: Added comments and documentation
    26 Oct 2022: Converted all database operations to parameterized stored procedures to increase security
    27 Oct 2022: Added command line switch for SQL operations
    27 Oct 2022: Added option to disable terminal server logging
    27 Oct 2022: Added location parameter for alternate drive mappings
    27 Oct 2022: Modified MapDrive and UnMapDrive to use NET USE, as PowerShell cmdlets map invisible drives
    07 Nov 2022: Added debug switch along with debugging log code.  Added UPN collection to Logging function
    08 Nov 2022: Created variables for drive mapping data structure.  Added MapAllDrives function to handle bulk drive mapping based on location parameter
    09 Nov 2022: Added CheckForAlert function to handle periodic alerts.  Commented ProfileRedirection, as those functions have been moved to the calling batch
    10 Nov 2022: Moved all variable values to prefs.json - v3.0
    15 Nov 2022: Removed as many uses of Get-CimInstance as possible.  It is slow, especially during login events.  Switched to registry reads where possible, or direct calls to the kernel otherwise.
    16 Nov 2022: Added version number in debug logging; rearranged location of SQLConnection.Open to just prior to use to prevent timeout
    16 Nov 2022: Added FastLog
    13 Dec 2022: Added additional logging to HardwareInventory.  Switched hard drive data from PowerShell cmdlet to C# class
    04 Dec 2023: Added OSInstallDate capture to HardwareInventory
    07 Feb 2023: Added LastBoot Timestamp to HardwareInventory
    08 May 2023: Added code to wait for domain network
    24 Jul 2023: Added DOC copy code
    25 Jul 2023: Added RunPeriodic function and Write-Log function.  Changed all calls to $Global:DebugWriter to Write-Log.
    02 Nov 2023: Added support for invocation of scheduled task list
    12 Dec 2023: Added function for updating wwwHomePage attribute per DHA standards
    12 Dec 2023: Added support for self-deleting tasks
    18 Dec 2023: Added support for Image-Based TipoftheDay popups
    20 Dec 2023: Added support for DB-Based TipoftheDay popups
    27 Dec 2023: Added support for Xaml within prefs.json
    28 Dec 2023: Added support for printer removal
    02 Apr 2024: Added support for Safety popup using DB-Based TipoftheDay function
    14 Mar 2025: Changed timestamp in Write-Log
    14 Mar 2025: Revamped Write-Log into Logging class. Replaced all references to Logging.Append
    14 Mar 2025: Added DataCaching methods
    14 Mar 2025: Added ProcessLaunch method and JSON properties
    17 Mar 2025: Added ConfigPath script parameter
#>
using namespace System.Collections.Generic
using namespace System.Text
using namespace System.IO

param (
    [string]$ConfigPath,
    [string]$Location,
    [switch]$UseSQL,
    [switch]$debug
)
$Error.Clear()

#######################################################################################
#                            LOAD CUSTOM LIBRARIES                                    #
#######################################################################################

$baseFolder = [Directory]::GetParent($ConfigPath)
$dllFolder = [Path]::Combine($baseFolder, "Assemblies")
$eudLogger = [Path]::Combine($dllFolder, "SapphTools.Logging.EudLogging.dll")
$debugLogger = [Path]::Combine($dllFolder, "SapphTools.Logging.SapphLogger.dll")
$null = [System.Reflection.Assembly]::LoadFrom($eudLogger)
$null = [System.Reflection.Assembly]::LoadFrom($debugLogger)

#######################################################################################
#                            INITIALIZE DEBUG LOGS                                    #
#######################################################################################


Set-Location C:
$Logger = [SapphTools.Logging.SapphLogger]::new()
$Logger.Log($env:USERNAME)
$Logger.Log($env:COMPUTERNAME)
$Logger.Log('Script Start - v3.4.0')

#######################################################################################
#                             FUNCTIONS BEGIN HERE                                    #
#######################################################################################

$Logger.Log('Environment: Implementing functions')
Function LL {
<#
.SYNOPSIS
    A quick and dirty wrapper for the SapphTools.Logging.LL enum (which is, itself, a clone of the Microsoft.Extensions.Logging.LogLevel enum)
.PARAMETER LogLevel
    Required. The string value of the enum
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    SapphTools.Logging.LL  An enum that indicates the LogLevel severity
#>
    [OutputType([SapphTools.Logging.LL])]
    param (
        [string]$LogLevel = "Information"
    )
    return [Enum]::Parse([SapphTools.Logging.LL], $LogLevel)
}

Function GenerateSQLConnection {
<#
.SYNOPSIS
    A pretty wrapper for the System.Data.SqlClient.SQLConnection constructor
.PARAMETER ServerName
    Required. Specifies the name of the SQL Server.  It should not be formatted as a UNC path, but may be an FQDN
.PARAMETER DBName
    Required. Specifies the name of a database on the provided server.
.PARAMETER Username
    Optional. Only used if Kerberos integrated security is not used. If used, a password must be provided
.PARAMETER Password
    Optional. Only used if Kerberos integrated security is not used. If used, a username must be provided
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.Data.SQLClient.SQLConnection  A connection object to the specified server and database. Returns null if ServerName is not a valid hostname
#>
    [OutputType([System.Data.SqlClient.SQLConnection])]
    param (
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$DBName,
        [ref]$Logger
    )
    $Logger.Log('GenerateSQLConnection: Begin')
    if ($ServerName -match '(?=^\\\\)?(?<server>[a-z0-9-]*)$') {
        $connectionString = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
        $connectionString["Server"] = $Matches.server
        $connectionString["Initial Catalog"] = $DBName
        if ($Username -and $Password) {
            $connectionString["Persist Security Info"] = $false
            $connectionString["User ID"] = $Username
            $connectionString["Password"] = $Password.ToString()
        } else {
            $connectionString["Integrated Security"] = $true
        }
        try {
            $c = New-Object System.Data.SqlClient.SQLConnection($connectionString.ToString())
            $Logger.Log('GenerateSQLConnection: Sucessfully instantiated SQLConnection object')
            return $c
        } catch {
            $Logger.Log($(LL('Error')). 'GenerateSQLConnection: Failed to instantiate SQLConnection object')
            return $null
        }
    } else {
            $Logger.Log($(LL('Error')), 'GenerateSQLConnection: Invalid server name')
        return $null
    }
}

Function CloseSQLConnection {
<#
.SYNOPSIS
    Closes and disposes of a specified SQLConnection
.PARAMETER Connection
    Required. Specifies a SQLConnection
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    No explicit outputs, however the SQLConnection is passed by referenced, and modified by this function
#>
    param (
        [Parameter(Mandatory=$true)][System.Data.SqlClient.SQLConnection]$Connection,
        [ref]$Logger
    )
    $Connection.Close()
    $Connection.Dispose()
    $Logger.Log('CloseSQLConnection: Closed connection and disposed of SQLConnection object')
}

Function CleanCerts {
<#
.SYNOPSIS
    Removes unneeded certificates from Personal certificate store
.PARAMETER userEDIPI
    Required. Specifies the current user's EDIPI for pattern matching
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None.
#>
    param (
        [string]$userEDIPI,
        [ref]$Logger
    )
    try {
        Push-Location Cert:\CurrentUser\My
        $PersonalStore = Get-ChildItem | Sort-Object -Property Subject
        $CurrentExp = New-Object System.Collections.Generic.List[datetime]
        $CodeSigningType = [Microsoft.PowerShell.Commands.EnhancedKeyUsageRepresentation]::new("Code Signing","1.3.6.1.5.5.7.3.3")
        foreach ($Cert in $PersonalStore) {
            if ($Cert.FriendlyName.Contains('CN=') -and
            $Cert.Subject.Contains($userEDIPI)) {
                $Logger.Log('CleanCerts: ARA Cert retained')
                continue
            }
            if ($Cert.FriendlyName.StartsWith('Signature') -and $Cert.EnhancedKeyUsageList -contains $CodeSigningType) {
                $Logger.Log('CleanCerts: Code Signing Cert Retained')
                continue
            }
            if ($Cert.FriendlyName.StartsWith('Encryption') -or
            $Cert.FriendlyName.StartsWith('Signature') -or
            $Cert.FriendlyName.StartsWith('Authentication')) {
                if (-not $Cert.Subject.Contains($userEDIPI)) {
                    $Logger.Log('CleanCerts: Foreign Cert Removed')
                    $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                    Remove-Item $CertPath
                    continue
                }
                if ([datetime]$Cert.GetExpirationDateString() -lt [datetime]::Now) {
                    $Logger.Log('CleanCerts: Expired Cert Removed')
                    $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                    Remove-Item $CertPath
                    continue
                }
                if ($Cert.FriendlyName.StartsWith('Authentication')) {
                    $CurrentExp.Add([datetime]$Cert.GetExpirationDateString())
                }
                $Logger.Log('CleanCerts: Core certs retained')
                continue
            }
            if ($Cert.Subject.Contains('Adobe')) {
                $Logger.Log('CleanCerts: Adobe Certs Removed')
                $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                Remove-Item $CertPath
                continue
            }
            if ($Cert.Subject.Contains('SERIALNUMBER=')) {
                if ($CurrentExp.Contains([datetime]$Cert.GetExpirationDateString())) {
                    $Logger.Log('CleanCerts: Component cert retained')
                    continue
                } else {
                    $Logger.Log('CleanCerts: Component cert removed for exp mismatch')
                    $CertPath = (Get-ChildItem | Where-Object {$_.Thumbprint -eq $Cert.Thumbprint} | Select-Object -Property PSPath).PSPath
                    Remove-Item $CertPath
                    continue
                }
            }
        }
    } catch {
        $Logger.Log($(LL('Debug')), 'CleanCerts: Error Generated', $_)
    } finally {
        Pop-Location
    }
}

Function WebAttributeCheck {
<#
.SYNOPSIS
    Reads and updates wwwHomePage value from AD according to DHA standards
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    Boolean.  If user has OneDrive configured, returns true. Else returns false
#>
    param (
        [boolean]$Clean = $false,
        [ref]$Logger
    )
    $GetDetailsOf_AVAILABILITY_STATUS = 303
    $Exception = ""
    try {
        $Logger.Log('PIV Check: Starting check')
        Import-Module pki
        Push-Location Cert:\CurrentUser\My

        $OneDriveEpoch = [System.DateTime]::ParseExact('10-18-23','MM-dd-yy',$null)

        $UserDataDefinition = @("UPN","HOST","EMAIL","CERTEXP","CA","ODStatus","UPDATE")

        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=$($env:USERNAME)))"
        $Searcher.SearchRoot = "LDAP://DC=med,DC=ds,DC=osd,DC=mil"
        $null = $Searcher.PropertiesToLoad.Add("wwwhomepage")
        $null = $Searcher.PropertiesToLoad.Add("userprincipalname")
        $null = $Searcher.PropertiesToLoad.Add("CN")
        $null = $Searcher.PropertiesToLoad.Add("mail")
        $User = $Searcher.FindOne()
        $UserDataStore = New-Object System.Collections.Generic.Dictionary"[String,String]"
        if ($User.Properties.mail[0] -match 'navy\.mil' -or $User.Properties.userprincipalname[0].Substring(11,4) -eq '1700') {
            $Exception = "Navy"
        } elseif (($User.Properties.mail[0] -match 'af\.mil' -or $User.Properties.userprincipalname[0].Substring(11,4) -eq '5700')) {
            $Exception = "Air Force"
        } elseif ($User.Properties.cn[0] -match 'MHIC') {
            $Exception = "MHIC"
        }
        if ([string]::IsNullOrWhiteSpace($User.Properties.wwwhomepage[0])) {
            for ($i = 0; $i -lt $UserDataDefinition.Count; $i ++) {
                $thisdef = $UserDataDefinition[$i]
                $UserDataStore.Add($thisdef, "")
            }
        } else {
            $DataArray = $User.Properties.wwwhomepage[0].Split('|')
            for ($i = 0; $i -lt $DataArray.Count; $i ++) {
                if ($i -ge $UserDataDefinition.Count) {
                    $thisdef = "Misc$($i)"
                } else {
                    $thisdef = $UserDataDefinition[$i]
                }
                $UserDataStore.Add($thisdef, $DataArray[$i])
            }
        }
        $userEDIPI = $User.Properties.userprincipalname[0].Substring(0,10)
        if ($Clean) {
            CleanCerts($userEDIPI, [ref]$Logger)
        }
        $UserDataStore["UPDATE"] = (Get-Date).ToString('MM-dd-yy')
        foreach ($cert in (Get-ChildItem)) {
            $Logger.Log("PIV Check: Cert: $($cert.Thumbprint) :: $($cert.Subject)")
            $Logger.Log("    PIV Check: Cert PN: $($cert.Extensions.Format(1) -match 'Principal name=')")
            $Logger.Log("    PIV Check: Cert PI: $($cert.Extensions.Format(1) -match 'Policy Identifier=2.16.840.1.101.')")
            $Logger.Log("    PIV Check: Cert Issuer: $($cert.Issuer)")
            $Logger.Log("    PIV Check: Cert Exp: $([datetime]$cert.GetExpirationDateString())")
        }
        $certAuth = Get-ChildItem |
            Where-Object {
                $_.Extensions.Oid.FriendlyName.Contains("Subject Alternative Name") -and
                    ($_.Extensions.Format(1) -match 'Principal name=') -and
                    ($_.Extensions.Format(1) -match 'Policy Identifier=2.16.840.1.101.3.2.1.3.13') -and
                    ((New-TimeSpan -Start $(Get-Date) -End $([datetime]$_.GetExpirationDateString())).Days -ge 0) -and
                    $_.Issuer.Contains("U.S. Government")
            } |
            Sort-Object -Property NotAfter -Descending |
            Select-Object -First 1

        $certEnc = Get-ChildItem |
            Where-Object {
                $_.Extensions.Oid.FriendlyName.Contains("Subject Alternative Name") -and
                $_.Extensions.Format(1)[6] -match 'RFC822 Name' -and
                $_.Extensions.Format(1)[3] -match "Policy Identifier=2.16.840.1.101.2.1.11.39" -and
                ((New-TimeSpan -Start $(Get-Date) -End $([datetime]$_.GetExpirationDateString())).Days -ge 0) -and
                $_.Issuer.Contains("DOD EMAIL") -and
                $_.Subject.Contains($userEDIPI)
            } |
            Sort-Object -Property NotAfter -Descending |
            Select-Object -First 1

        if($certAuth){
	        $UserDataStore["UPN"] = [regex]::Match($certAuth.Extensions.Format(1)[6], "(?<piv>\d{16}@mil)").Value
	        $UserDataStore["CERTEXP"] = $certAuth.NotAfter.ToString('MM-dd-yy')
	        $UserDataStore["CA"] = [regex]::Match($certAuth.Issuer, '(?:^CN=DOD ID )(?<ca>CA-\d*)').Groups['ca'].Value
        }else{
	        $UserDataStore["UPN"] = "NOPIV"
	        $UserDataStore["CERTEXP"] = ""
	        $UserDataStore["CA"] = ""
        }
        $Logger.Log("PIV Check: UPN: $($UserDataStore["UPN"])")
        $Logger.Log("PIV Check: CERTEXP: $($UserDataStore["CERTEXP"])")
        $Logger.Log("PIV Check: CA: $($UserDataStore["CA"])")
        if($certEnc){
	        $UserDataStore["EMAIL"] = [regex]::Match($certEnc.extensions.format(1)[6], '(?:RFC822 Name=)(?<email>.*\.mil)').Groups['email'].Value
        }else{
	        $UserDataStore["EMAIL"] = "NoEmailCert"
        }
        $Logger.Log("PIV Check: EMAIL: $($UserDataStore["EMAIL"])")
        $UserDataStore["HOST"] = $env:computername
        $Logger.Log("PIV Check: HOST: $($UserDataStore["HOST"])")
        $date = New-Object DateTime
        if (
            [DateTime]::TryParseExact($UserDataStore["UPDATE"], 'MM-dd-yy', $null, [System.Globalization.DateTimeStyles]::None, [ref] $date) -and
            $date -gt $OneDriveEpoch -and
            $UserDataStore["ODStatus"] -eq "OneTrue"
        ) {
            $UserDataStore["ODStatus"] = "OneTrue"
            $OneDriveEnabled = $true
            $Logger.Log("PIV Check: ODStatus: OneTrue selected based on previous state")
        } else {
            try {
	            $OneDriveDocs = "$env:OneDrive\Documents"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDriveDocs))
	            $DocsStatus = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDriveDocs -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            $OneDriveDesk = "$env:OneDrive\Desktop"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDriveDesk))
	            $DeskStatus = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDriveDesk -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            $OneDrivePics = "$env:OneDrive\Pictures"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDrivePics))
	            $PicsStatus = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDrivePics -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            $OneDrivePics2 = "$env:OneDrive\My Pictures"
	            $Shell = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $OneDrivePics2))
	            $PicsStatus2 = $Shell.getDetailsOf(($Shell.ParseName((Split-Path $OneDrivePics2 -Leaf))),$GetDetailsOf_AVAILABILITY_STATUS)
	            if (($DocsStatus -match "Available") -or
                    ($DeskStatus -match "Available") -or
                    ($PicsStatus -match "Available") -or
                    ($PicsStatus2 -match "Available") -or
                    ($DocsStatus -match "Sync") -or
                    ($DeskStatus -match "Sync") -or
                    ($PicsStatus -match "Sync") -or
                    ($PicsStatus2 -match "Sync")
                ){
		            $UserDataStore["ODStatus"] = "OneTrue"
                    $OneDriveEnabled = $true
                    $Logger.Log("PIV Check: ODStatus: OneTrue selected based  on folder state")
	            } else {
		            $UserDataStore["ODStatus"] = "OneFalse"
                    $OneDriveEnabled = $false
                    $Logger.Log("PIV Check: ODStatus: OneFalse selected based on folder state")
	            }
                $Logger.Log("    PIV Check: ODStatus: Documents exist: $([System.IO.Directory]::Exists("$env:OneDrive\Documents"))")
                $Logger.Log("    PIV Check: ODStatus: Desktop exist: $([System.IO.Directory]::Exists("$env:OneDrive\Desktop"))")
                $Logger.Log("    PIV Check: ODStatus: Pictures exist: $([System.IO.Directory]::Exists("$env:OneDrive\Pictures"))")
                $Logger.Log("    PIV Check: ODStatus: My Pictures exist: $([System.IO.Directory]::Exists("$env:OneDrive\My Pictures"))")
                $Logger.Log("    PIV Check: ODStatus: Documents state: $DocsStatus")
                $Logger.Log("    PIV Check: ODStatus: Desktop state: $DeskStatus")
                $Logger.Log("    PIV Check: ODStatus: Pictures state: $PicsStatus")
                $Logger.Log("    PIV Check: ODStatus: My Pictures state: $PicsStatus2")
            } catch {
                $UserDataStore["ODStatus"] = "OneFalse"
                $OneDriveEnabled = $false
                $Logger.Log($(LL('Debug')), "PIV Check: ODStatus: OneFalse selected based on error state", $error)
            }
        }
        $Logger.Log("PIV Check: ODStatus: $($UserDataStore["ODStatus"])")
        $sb = New-Object System.Text.StringBuilder
        $isFirst = $true
        foreach ($item in $UserDataStore.Values) {
            if ($isFirst) {
                [void]$sb.Append($item)
                $isFirst = $false
            } else {
                [void]$sb.Append("|$($item)")
            }
        }

        $UserDE = [ADSI]($User.Path)
        $UserDE.Put("wwwhomepage",$sb.ToString())
        $UserDE.SetInfo()
        $Logger.Log('PIV Check: Check complete')
    } catch {
        $Logger.Log('PIV Check: Check failed')
    } finally {
        Pop-Location
    }
    return @{ OneDrive = $OneDriveEnabled; Ex = $Exception }
}

Function RunPeriodic {
<#
.SYNOPSIS
    Checks if current day matches input
.PARAMETER Day
    Required. Specifies the day of week to be checked against
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    Boolean.  If input matches, returns true. Else returns false
#>
    param (
        [Parameter(Mandatory=$true)][string]$Day
    )
    return ($Day -eq (Get-Date).DayOfWeek)
}

Function Get-UserGroup {
<#
.SYNOPSIS
    Returns a string[] of the user's direct group memberships (no recursion)
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    System.String[]. The group names from user's memberOf property
#>
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=$($env:USERNAME)))"
    $Searcher.SearchRoot = "LDAP://DC=med,DC=ds,DC=osd,DC=mil"
    $null = $Searcher.PropertiesToLoad.Add("memberOf")
    $User = $Searcher.FindOne()
    return (($User.Properties.memberof | Select-String -Pattern 'CN=(?<group>[^,]*)' -AllMatches).Matches.Groups | Where-Object {$_.Name -eq 'group'} | Select-Object Value).Value
}

Function MapDrive {
<#
.SYNOPSIS
    Creates smb drive mappings using net use
.PARAMETER Letter
    Required. Specifies the drive letter to be mapped
.PARAMETER UNC
    Required. Specifies the UNC path to be mapped
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    Boolean.  On failure will return $false, otherwise will return $null
#>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$true)][string]$Letter,
        [Parameter(Mandatory=$true)][string]$UNC,
        [ref]$Logger
    )
    $Logger.Log("MapDrive: Begin attempt to map $UNC")
    try {
        $null = ([System.IO.DirectoryInfo]::new($UNC)).GetDirectories()
    } catch {
        $Logger.Log("MapDrive: Function exited.  User does not have rights to $UNC")
        return $null
    }
    if ($Letter -match '(?<letter>[A-Za-z])') {
        $Letter = -join($Matches.letter, ':')
    } else {
        $Logger.Log($(LL('Error')), "MapDrive: Invalid drive letter '$letter'")
        return $null
    }
    if ($Letter.Substring(0,1) -in (Get-PSDrive | Select-Object Name).Name) {
        $Logger.Log("MapDrive: Skipped already mapped '$letter'")
        return $null
    }
    try {
        if ($PSCmdlet.ShouldProcess($unc)) {
            net use $letter $unc /PERSISTENT:YES
            $Logger.Log("MapDrive: Sucessfully mapped drive $letter.")
        } {
            $Logger.Log("MapDrive: Mapping of $letter prevented by ShouldProcess")
        }
    } catch {
        $Logger.Log($(LL('Error')), "MapDrive: Net use command failed with letter $letter and path $unc")
        return $false
    }
    trap [System.UnauthorizedAccessException] {
        $Logger.Log("MapDrive: Function exited.  User does not have rights to $UNC")
    }
}

Function MapAllDrives {
<#
.SYNOPSIS
    Bulk drive mapping based on specific List and Hashtable data structures
.PARAMETER Location
    Required. Specifies the Location parameter provided to the script
.PARAMETER LocationList
    Required. A String-based Generic List of all locations
.PARAMETER MappingList
    Required. A Hashtable array-based Generic List of mappings that correspond in order to locations in LocationList
.Parameter GlobalMaps
    Optional. A Hashtable-based Generic List of maps that apply to all users
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param(
        [string]$Location,
        [List[String]]$LocationList,
        [List[Hashtable[]]]$MappingList,
        [List[Hashtable]]$GlobalMaps,
        [ref]$Logger
    )
    $Logger.Log('MapAllDrives: Begin')
    if ($GlobalMaps) {
        $Logger.Log('MapAllDrives: GlobalMaps')
        foreach ($Mapping in $GlobalMaps) {
            $null = MapDrive($Mapping.Letter, $Mapping.UNC, [ref]$Logging)
        }
    }
    if (($Location -eq $LocationList[$LocationList.Count-1]) -or ($null -eq $Location) -or ($Location.Length -eq 0)) {
        $Logger.Log('MapAllDrives: DefaultMaps')
        foreach ($Mapping in $MappingList[$LocationList.Count-1]) {
            $null = MapDrive($Mapping.Letter, $Mapping.UNC, [ref]$Logging)
        }
        return
    }
    for($i=0;$i -lt $LocationList.Count-1;$i++) {
        if ($Location -eq $LocationList[$i]) {
            $Logger.Log('MapAllDrives: LocationMaps')
            foreach ($Mapping in $MappingList[$i]) {
                $null = MapDrive($Mapping.Letter, $Mapping.UNC, [ref]$Logging)
            }
            break
        }
    }
}

Function Set-SpecialtyDrive {
<#
.SYNOPSIS
    Bulk drive mapping based on specific List and Hashtable data structures
.PARAMETER Location
    Required. Specifies the Location parameter provided to the script
.PARAMETER LocationList
    Required. A String-based Generic List of all locations
.PARAMETER MappingList
    Required. A Hashtable array-based Generic List of mappings that correspond in order to locations in LocationList
.Parameter GlobalMaps
    Optional. A Hashtable-based Generic List of maps that apply to all users
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$UserGroups,
        [List[SpecialtyMap]]$SpecialtyList,
        [ref]$Logger
    )
    $Logger.Log('Set-SpecialtyDrives: Begin')
    foreach ($SpecialtyMap in $SpecialtyList) {
        if ($UserGroups -contains $SpecialtyMap.Group) {
            if ($PSCmdlet.ShouldProcess($SpecialtyMap.UNC)) {
                $null = MapDrive($SpecialtyMap.Letter, $SpecialtyMap.UNC, [ref]$Logger)
            }
        }
    }
}

Function UnmapDrive {
<#
.SYNOPSIS
    Unmaps one or more drives as a wrapper for net use
.PARAMETER Letters
    Required. Specifies an array of strings that represent drive letters.  If multi-character strings are passed, only the first character in each string will be processed
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string[]]$Letters,
        [ref]$Logger
    )
    foreach ($Letter in $Letters) {
        if ($Letter -match '(?<letter>[A-Za-z])') {
            $Letter = -join($Matches.letter, ':')
            try {
                net use $Letter /DELETE /Y
                $Logger.Log("MapDrive: Sucessfully unmapped drive $letter.")
            } catch {
                $Logger.Log($(LL('Error')), "UnmapDrive: failed to unmap drive $letter.  Not unexpected")
            }
        } else {
            $Logger.Log($(LL('Error')), "UnmapDrive: Invalid drive letter '$letter'")
            continue
        }
    }
}

Function ProfileRedirection {
<#
.SYNOPSIS
    Redirects user profile folders to network HomeShare locations
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param(
        [ref]$Logger
    )
    try {
        $OneDrive = "$($env:USERPROFILE)\OneDrive - militaryhealth"
        $shellFolders = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        $userShellFolders = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $destinations = $shellFolders, $userShellFolders
        $Logger.Log("ProfileRedirection: OneDrivePath $OneDrive")
        if ([System.IO.Directory]::Exists($OneDrive)) {
            $Logger.Log("ProfileRedirection: OneDrivePath Detected")
            foreach ($destination in $destinations) {
                $Logger.Log("ProfileRedirection: Setting Keys At $destination")
                Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($OneDrive)\Documents"
                Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($OneDrive)\My Music"
                Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($OneDrive)\My Pictures"
                Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($OneDrive)\My Video"
            }
        } else {
            $Logger.Log("ProfileRedirection: OneDrivePath Not Detected")
            foreach ($destination in $destinations) {
                $Logger.Log("ProfileRedirection: Setting Keys At $destination")
                Set-ItemProperty -Path $destination -Name 'Personal' -Value "$($env:USERPROFILE)\Documents"
                Set-ItemProperty -Path $destination -Name 'My Music' -Value "$($env:USERPROFILE)\My Music"
                Set-ItemProperty -Path $destination -Name 'My Pictures' -Value "$($env:USERPROFILE)\My Pictures"
                Set-ItemProperty -Path $destination -Name 'My Video' -Value "$($env:USERPROFILE)\My Video"
            }
        }
        $Logger.Log('ProfileRediction: Modified user shell folders')
    } catch {
        $Logger.Log($(LL('Error')), 'ProfileRediction: Failed to modify user shell folders')
    }
}

Function IndividualFileManagement {
<#
.SYNOPSIS
    General maintenance actions requested by IA/Cyber
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [ref]$Logger
    )
    $Logger.Log("IndividualFileManagement: Removing hard coded files")
    Remove-Item -Recurse -Force -Path "$($env:LOCALAPPDATA)\OneLaunch" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Force -Path C:\Windows\SysWOW64\msxml4.dll -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Force -Path C:\Windows\SysWOW64\msxml4r.dll -Confirm:$false -ErrorAction SilentlyContinue
}

Function LocalFileCopy {
<#
.SYNOPSIS
    File copy for DOC/Critical Events
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [ref]$Logger
    )
    $Logger.Log("LocalFileCopy: Copying list of hard coded files")
}

Function LaunchProcesses {
<#
.SYNOPSIS
    Launch arbitrary processes as part of startup
.PARAMETER $PSIList
    Specifies a List of type ProcessStartInfo. These objects will be used to launch processes with the FileName and Arguments. No other PSI properties are honored.
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [List[System.Diagnostics.ProcessStartInfo]]$PSIList,
        [ref]$Logger
    )
    $Logger.Log("LaunchProcess begin")
    foreach ($Psi in $PSIList) {
        Start-Process -FilePath $Psi.FileName -ArgumentList $Psi.ArgumentList -WindowStyle Hidden
    }
}

Function CheckForAlert {
<#
.SYNOPSIS
    Decides whether to call CallAlert based on if CallAlert is only desired periodically, and if it is within the desired window
.PARAMETER baseDate
    Required if doPeriodic is True. The base date off which periodicy is calculated
.PARAMETER Interval
    Required if doPeriodic is True. The periodicy interval.
.PARAMETER missedAlertWindow
    Required if doPeriodic is True. The number of days after the interval window a missed alert will still fire.
.PARAMETER doPeriodic
    If false, this function is a wrapped for CallAlert.
.PARAMETER AlertFile
    Required. Specifies the file to be launched.  Generally expected to be an HTA file
.PARAMETER RunOnServer
    Optional. Specifies whether execution should terminate on server OSes.  Defaults to $false
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param(
        [Parameter(Mandatory=$true)][string]$AlertFile,
        [ref]$Logger,
        [datetime]$baseDate,
        [int]$Interval,
        [int]$missedAlertWindow,
        [switch]$doPeriodic,
        [switch]$RunOnServer = $false
    )


    #Base dir
    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $basedir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $basedir = $env:USERPROFILE
    }

    if (Test-Path "$basedir\noalert.txt") {
        $Logger.Log('CheckForAlert: Exempt')
        return $null
    }

    if ((whoami /upn) -match '\.ad(s|w)@mil$') {
        $Logger.Log('CheckForAlert: Exempt')
        return $null
    }

    #If we aren't doing periodic alerts, just forward to CallAlert and move on
    if (-not $doPeriodic) {
        $Logger.Log('CheckForAlert: Non-periodic CallAlert')
        return CallAlert -AlertFile $AlertFile -RunOnServer:$RunOnServer
    }

    #How long has it been since the last intended alert day?
    $alertSpan = (New-TimeSpan -Start $baseDate -End $(Get-Date)).Days % $Interval

    #How long has it been since the last actual alert?
    if (-not (Test-Path "$basedir\alert.txt")) {
        $fileSpan = 30
    } else {
        $fileSpan = (New-TimeSpan -Start $((Get-ChildItem "$basedir\alert.txt").LastWriteTime) -End $(Get-Date)).Days
    }

    $todayIsInAlertWindow = ($alertSpan -le $missedAlertWindow)
    $fileDateIsWithinAlertWindow = ($fileSpan -le $missedAlertWindow)

    if ($todayIsInAlertWindow -and -not $fileDateIsWithinAlertWindow) {
        $Logger.Log('CheckForAlert: Periodic CallAlert')
        return CallAlert -AlertFile $AlertFile -RunOnServer:$RunOnServer
    } else {
        $Logger.Log('CheckForAlert: Out of phase for periodic CallAlert')
        return $null
    }
}

Function CallAlert {
<#
.SYNOPSIS
    Uses invoke item to launch a file, optionally skipping execution on server OSes.
    This function will write a 0-byte file to the user's homeshare to log the last time the user saw the alert.
.PARAMETER AlertFile
    Required. Specifies the file to be launched.  Generally expected to be an HTA file
.PARAMETER RunOnServer
    Optional. Specifies whether execution should terminate on server OSes.  Defaults to $false
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string]$AlertFile,
        [ref]$Logger,
        [switch]$RunOnServer = $false
    )
    $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption | Select-Object Caption).caption

    If (($osCaption -like '*server*') -and ($RunOnServer -eq $false)) {
        return $null
    }

    #Base dir
    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $basedir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $basedir = $env:USERPROFILE
    }

    if (Test-Path $AlertFile) {
        $Logger.Log('CallAlert: Alert file exists.')
        Invoke-Item $AlertFile
        Set-Content -Path "$basedir\alert.txt" -Value $null
        $(Get-Item "$basedir\alert.txt").lastwritetime=$(Get-Date)
    } else {
        return $null
    }
}

Function Show-Totd {
<#
.SYNOPSIS
    Displays an image from the appropriate day folder of the supplied base path.
.PARAMETER BasePath
    Required. Specifies the base path that contains the day folders.
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string]$BasePath,
        [ref]$Logger
    )
    $Logger.Log('Show-Totd: Invoked')

    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $profDir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $profDir = $env:USERPROFILE
    }

    if (Test-Path "$profDir\nototd.txt") {
        $Logger.Log('Show-Totd: Exempt')
        return
    }

    if ((whoami /upn) -match '\.ad(s|w)\@mil') {return}
    $TodaysPath = "$BasePath\$((Get-Date).DayOfWeek)"
    if (-not (Test-Path $TodaysPath)) {return}
    $Logger.Log('Show-Totd: TodayPath Exists')
    $image = Get-ChildItem -path $TodaysPath -Recurse -Include  *.png,*.jpg,*.jpeg,*.bmp -Name | Sort-Object -Property LastWriteTime | Select-Object -last 1
    if ($null -eq $image) {return}
    $Logger.Log('Show-Totd: Image in TodayPath Exists')
    $imagePath = "$($TodaysPath)\$($image)"
    $file = Get-Item ($imagePath)
    $Logger.Log("Show-Totd: TargetImage: $file")
    [void][reflection.assembly]::LoadWithPartialName("System.Drawing")
    $img = [System.Drawing.Image]::FromFile($file)
    [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $form = New-Object Windows.Forms.Form
    $form.Text = "Image Viewer"
    $form.Width = $img.Size.Width
    $form.Height = $img.Size.Height
    $pictureBox = New-Object Windows.Forms.PictureBox
    $pictureBox.Width = $img.Size.Width
    $pictureBox.Height = $img.Size.Height
    $pictureBox.Image = $img
    $form.Controls.Add($pictureBox)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.Add_Shown( { $form.Activate() } )
    $Logger.Log('Show-Totd: Image Displayed')
    $form.ShowDialog()
}

Function Show-NewTotd {
<#
.SYNOPSIS
    Displays a Tip of the Day from a supplied Database.
.PARAMETER ServerName
    Required. Specifies the name of the SQL Server.  It should not be formatted as a UNC path, but may be an FQDN
.PARAMETER DBName
    Required. Specifies the name of a database on the provided server.
.PARAMETER ImagePath
    Required. Specifies the full path of an image referenced by the XAML
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None
#>
    param (
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$DBName,
        [Parameter(Mandatory=$true)][string]$ImagePath,
        [Parameter(Mandatory=$true)][xml]$Xaml,
        [ref]$Logger
    )
    $Logger.Log('Show-NewTotd: Invoked')

    if (Test-Path "$($env:USERPROFILE)\OneDrive - militaryhealth") {
        $profDir = "$($env:USERPROFILE)\OneDrive - militaryhealth"
    } else {
        $profDir = $env:USERPROFILE
    }

    if ((Test-Path "$profDir\nototd.txt") -or ((whoami /upn) -match '\.ad(s|w)\@mil')) {
        $Logger.Log('Show-NewTotd: Exempt')
        return
    }

    $connection = GenerateSQLConnection($ServerName, $DBName, [ref]$Logger)

    $Logger.Log('Show-NewTotd: Retrieving Tip')
    $cmd = New-Object System.Data.SqlClient.SqlCommand -Property @{
        Connection = $connection
        CommandType = [System.Data.CommandType]::StoredProcedure
        CommandText = "dbo.sp_GetTip"
    }

    [void]$cmd.Parameters.Add("@UserID", [System.Data.SqlDbType]::VarChar)
    $cmd.Parameters["@UserID"].Value = $env:USERNAME

    $dt = New-Object System.Data.DataTable
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $returned = $adapter.Fill($dt)

    $connection.Close()
    if ($returned -eq 0 -or $null -eq $dt.TipID_PK -or $dt.TipID_PK -is [System.DBNull]) {
        $Logger.Log('Show-NewTotd: No Tip Found')
        return
    }

    $Title = $dt.Title
    $TipText = $dt.Tip
    $DisplayDate = $dt.DisplayDate

    $dt.Dispose()
    $Logger.Log('Show-NewTotd: Tip Found, Constructing Display')

    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')    | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')   | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')          | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration') | Out-Null

    $TipReader = New-Object System.Xml.XmlNodeReader($Xaml)
    $TipWindow = [System.Windows.Markup.XamlReader]::Load($TipReader)

    $Tip_imgBulb = $TipWindow.FindName("imgBulb")
        $Tip_imgBulb.Source = New-Object System.Windows.Media.Imaging.BitmapImage($ImagePath)
    $Tip_lblDate = $TipWindow.FindName("lblDate")
        $Tip_lblDate.Content = $DisplayDate
    $Tip_lblTitle = $TipWindow.FindName("lblTitle")
        $Tip_lblTitle.Content = $Title
    $Tip_txbTip = $TipWindow.FindName("txbTip")
        $Tip_txbTip.Text = $TipText
    $Tip_bntOK = $TipWindow.FindName("bntOK")
        $Tip_bntOK.Add_Click({ $TipWindow.Close() })

    $null = $TipWindow.ShowDialog()
    $Logger.Log('Show-NewTotd: Display Closed by User')
}

Function RemovePrinters {
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$InvalidPrintServers,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$InvalidPrinterNames,

        [ref]$Logger
    )
    $Logger.Log('RemovePrinters: Begin')
    $RemovalList = Get-Printer | Where-Object {$_.ComputerName -in $InvalidPrintServers -or $_.Name -in $InvalidPrinterNames}
    if ($RemovalList -is [ciminstance]) {
        $Logger.Log("RemovePrinters: Removing $($RemovalList.Name)")
        $RemovalList | Remove-Printer
    } elseif ($RemovalList -is [object[]]) {
        foreach ($Printer in $RemovalList) {
            $Logger.Log("RemovePrinters: Removing $($Printer.Name)")
        }
        $RemovalList | Remove-Printer
    } else {
        $Logger.Log('RemovePrinters: No matching printers to remove')
    }
}

Function HideWindow {
<#
.SYNOPSIS
    Implements the Winuser.h ShowWindow function from the Win32 API.  This will hide the window belonging to the current process.
    Note, this action cannot be undone.  The window will remain hidden until the process terminates.
.INPUTS
    None. You cannot pipe objects to HideWindow
.OUTPUTS
    None
.LINK
    https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
#>
    param (
        [ref]$Logger
    )
    $Logger.Log('HideWindow: Begin')
    if (-not (Test-Path variable:global:psISE)) {
        Add-Type -Name win -Member '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);' -Namespace native
        [native.win]::ShowWindow([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle, 0)
        $Logger.Log('HideWindow: Hidden.')
    } else {
        $Logger.Log('HideWindow: Not hidden.')
    }
}

Function InvokeScheduledTasks {
<#
.SYNOPSIS
    Invokes pre-installed scheduled tasks by name
.PARAMETER TaskList
    Required. String[] of scheduled tasks to be launched
.INPUTS
    None. You cannot pipe objects to this function
.OUTPUTS
    None.
#>
    param (
        [Parameter(Mandatory=$true)][string[]]$TaskList,
        [ref]$Logger
    )
    foreach ($TaskName in $TaskList) {
        try {
            Start-ScheduledTask -TaskName $TaskName
            $Logger.Log("InvokeScheduledTasks: Scheduled task created - $TaskName.")
        } catch {
            $Logger.Log($(LL('Error')), 'InvokeScheduledTasks: Scheduled task creation failed.')
        }
    }
}

Function Initialize-EudLogger {
    [OutputType([SapphTools.Logging.EudLogger])]
    param (
        [PSCustomObject]$Preferences,
        [bool]$SQLOverride,
        [ref]$Logger
    )
    $eudLogger = [SapphTools.Logging.EudLogger]::new()
    $loggingPaths = [SapphTools.Logging.FileLoggingPaths]::new()
    $loggingPaths.MachineLogs = $Preferences.FileVariables.MachineLogsLoc
    $loggingPaths.MachineStats = $Preferences.FileVariables.MachineStatsLoc
    $loggingPaths.UserLogon = $Preferences.FileVariables.UserLogonLoc
    $loggingPaths.ComputerLogon = $Preferences.FileVariables.ComputerLogonLoc
    $loggingPaths.PrinterLogs = $Preferences.FileVariables.PrinterLogsLoc
    $loggingPaths.AppLogs = $Preferences.FileVariables.ApplicationLogsLoc
    $loggingPaths.StatLogs = $Preferences.FileVariables.HardwareInvLoc

    $eudLogger.SetLoggingPaths($loggingPaths)
    $eudLogger.SiteCode = $Preferences.GlobalVariables.SiteCode
    $server = $Preferences.DatabaseVariables.DatabaseServer
    $database = $Preferences.DatabaseVariables.DatabaseName
    $eudLogger.Connection = GenerateSQLConnection($server, $database, [ref]$Logger)
    $eudLogger.LogToDB = $Preferences.LoggingOverrides.LogToDB -or $SQLOverride
    $eudLogger.LogToFile = $Preferences.LoggingOverrides.LogToFiles
    $eudLogger.LogToTS = $Preferences.LoggingOverrides.LogTSData
    return $eudLogger
}

Function Update-LogCache {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$true)]
        [ref]$eudLogger
    )
    if (-not (Test-Path "$($env:APPDATA)\LLT")) {
        $null = New-Item -Path "$($env:APPDATA)" -Name 'LLT' -ItemType Directory
    }
    if (Test-Path "$($env:APPDATA)\LLT\cache.json") {
        if($PSCmdlet.ShouldProcess("$($env:APPDATA)\LLT\cache.json")) {
            $cache = Get-Content "$($env:APPDATA)\LLT\cache.json"
            if ($eudLogger.CacheNeeded) {
                $newCache = ""
                if ($eudLogger.TryGetCacheData($cache, $false, [ref]$newCache)) {
                    if ($newCache.Length -gt $cache.Length) {
                        Set-Content -Path "$($env:APPDATA)\LLT\cache.json" -Value $newCache
                    }
                } else {
                    Remove-Item "$($env:APPDATA)\LLT\cache.json" -Force
                }
            } else {
                $eudLogger.JsonCache = $cache
                if ($null -ne $eudLogger.TransmitCacheData()) {
                    Remove-Item "$($env:APPDATA)\LLT\cache.json" -Force
                }
            }
        }
    }
}

#######################################################################################
#                        PREFERENCE LOAD AND PARSE                                    #
#######################################################################################

$Logger.Log('Environment: Preference structure')

$prefs = Get-Content $ConfigPath | ConvertFrom-Json

$Logger.Log('Environment: Loaded preference file to memory')

class SpecialtyMap {
    [ValidateNotNullOrEmpty()][string]$Group
    [ValidateNotNullOrEmpty()][string]$Letter
    [ValidateNotNullOrEmpty()][string]$UNC
}

$FastLogLoc                          = $prefs.FileVariables.FastLogLoc
$AlertFile                           = $prefs.FunctionVariables.AlertFile
$GlobalPrinter                       = $prefs.FunctionVariables.GlobalPrinter
$TotdBasePath                        = $prefs.FunctionVariables.TotdBasePath
$TotdImage                           = $prefs.FunctionVariables.NewTotdImage
$TotdXaml                            = $prefs.FunctionVariables.NewTotdXaml
$SafetyXaml                          = $prefs.FunctionVariables.SafetyXaml
$InvalidPrintServers                 = $prefs.FunctionVariables.InvalidPrintServers
$InvalidPrinterNames                 = $prefs.FunctionVariables.InvalidPrinterNames
$DatabaseServer                      = $prefs.DatabaseVariables.DatabaseServer
$TotdDatabase                        = $prefs.DatabaseVariables.TotdDatabase
$SafetyDatabase                      = $prefs.DatabaseVariables.SafetyDatabase
$ScheduledTaskList                   = $prefs.ScheduledTaskList
$DrivesToUnMap                       = $prefs.MappingVariables.DrivesToUnmap
$StartDate                           = [convert]::ToDateTime($prefs.CheckForAlertVariables.StartDate)
$Span                                = $prefs.CheckForAlertVariables.Span
$DaysAfterAlertDateToShowMissedAlert = $prefs.CheckForAlertVariables.AlertWindow
$DoPeriodic                          = $prefs.CheckForAlertVariables.DoPeriodic
$Logger.LogFile                      = $prefs.FileVariables.DebugLogLoc

$Logger.Log('Environment: Generated simple variables from preferences')
if ($prefs.FunctionExecution.HideWindow) {
    $null = HideWindow
}
if (-not (Test-Path variable:global:psISE)) {
    Start-Sleep -Seconds 30
}
$LocationList                        = [List[String]]::new()
$MappingList                         = [List[Hashtable[]]]::new()
$GlobalMaps                          = [List[Hashtable]]::new()
$SpecialtyMaps                       = [List[SpecialtyMap]]::new()
$SpecialtyGroups                     = [List[String]]::new()
$ProcessList                         = [List[System.Diagnostics.ProcessStartInfo]]::new()
foreach ($map in $prefs.MappingVariables.GlobalMaps) {
    $GlobalMaps.Add(@{Letter=$map.Letter;UNC=$map.UNC})
}
foreach ($locationmap in $prefs.MappingVariables.LocationMaps) {
    $LocationList.Add($locationmap.Name)
    $temp = [List[Hashtable]]::new()
    foreach ($mapping in $locationmap.Mappings) {
        $temp.Add(@{Letter=$mapping.Letter;UNC=$mapping.UNC})
    }
    $MappingList.Add($temp)
}
$defaultmaps = [List[Hashtable]]::new()
foreach ($map in $prefs.MappingVariables.DefaultMaps.Mappings) {
    $defaultmaps.Add(@{Letter=$map.Letter;UNC=$map.UNC})
}
foreach ($default in $prefs.MappingVariables.DefaultMaps.PermittedNames) {
    $LocationList.Add($default)
    $MappingList.Add($defaultmaps)
}
foreach ($specialty in $prefs.MappingVariables.SpecialtyMaps) {
    $temp = [SpecialtyMap]@{
        Group = $specialty.Group
        Letter = $specialty.Letter
        UNC = $specialty.UNC
    }
    $SpecialtyMaps.Add($temp)
    $SpecialtyGroups.Add($specialty.Group)
}
$
foreach ($entry in $prefs.ProcessLaunch) {
    $thisPSI = [System.Diagnostics.ProcessStartInfo]::new()
    $thisPSI.FileName = $entry.FilePath
    foreach ($arg in $entry.ArgumentList) {
        $thisPSI.ArgumentList.Add($arg)
    }
    $ProcessList.Add($thisPSI)
}

$Logger.Log('Environment: Generated data structures from preferences')

# A Note About Function Order
# HideWindow is first because we want to vanish as quickly as possible - in fact, it has been moved inside Preference parsing
# CheckForAlert is second because we want loading the alert to mask further processing
# Logging is third because it returns a value useful in HardwareInventory. Get-NetIPAddress costs 3.1s, so if we can only do it once, all the better
# PrinterLogging, AppLogging, and HardwareInventory are interchangable
# Next, drive mappings are established, and general misc work is done
# At this time, I believe the items in IndividualFileManagement are no longer required, however the function remains as a placeholder for future IA requests

$eudLogger = Initialize-EudLogger($prefs, $UseSQL, [ref]$Logger)
$UserGroups = Get-UserGroup

if ($prefs.FunctionExecution.CheckForAlert) {
    CheckForAlert($AlertFile, [ref]$Logger, $StartDate, $Span, $DaysAfterAlertDateToShowMissedAlert, $DoPeriodic)
}
$ODStatus = $null
if ($prefs.FunctionExecution.WebAttributeCheck) {
    $clean = $prefs.FunctionExecution.CleanCerts
    $return = WebAttributeCheck($clean, [ref]$Logger)
    $ODStatus = $return.OneDrive.Where({$null -ne $_})[0]
    $eudLogger.ODStatus = $ODStatus
    $eudLogger.Exception = $return.Ex
}
if ($prefs.FunctionExecution.Logging) {
    $eudLogger.WriteAdapterData()
    $eudLogger.WriteLoginData()
}
if ($prefs.FunctionExecution.HardwareInventory) {
    $eudLogger.WriteStatData()
}
if ($prefs.FunctionExecution.PrinterLogging) {
    $eudLogger.WritePrinterData()
}
if ($prefs.FunctionExecution.AppLogging) {
    $eudLogger.WriteAppData()
}
if ($prefs.FunctionExecution.Unmap) {
    $null = UnmapDrive($DrivesToUnMap, [ref]$Logger)
}
if ($prefs.FunctionExecution.Map) {
    MapAllDrives($Location, $LocationList, $MappingList, $GlobalMaps, [ref]$Logger)
}
if ($prefs.FunctionExecution.SpecialtyMap) {
    if ($UserGroups | Where-Object {$SpecialtyGroups.ToArray() -contains $_}) {
        Set-SpecialtyDrives($UserGroups, $SpecialtyMaps, [ref]$Logger)
    }
}
if ($prefs.FunctionExecution.ProfileRedirection) {
    ProfileRedirection([ref]$Logger)
}
if ($prefs.FunctionExecution.IARemoval) {
    IndividualFileManagement([ref]$Logger)
}
if ($prefs.FunctionExecution.FastLog) {
    $Logger.Log('Environment: Writing fastlog')
    $filename = "$($env:COMPUTERNAME)-$($env:USERNAME).txt"
    $null = New-Item -Path $FastLogLoc -Name $filename -ItemType File -Force
    $(Get-Item "$($FastLogLoc)$($filename)").lastwritetime=$(Get-Date)
}
if ($prefs.FunctionExecution.LocalFileCopy) {
    LocalFileCopy([ref]$Logger)
}
if ($prefs.FunctionExecution.GlobalPrinterAdd) {
    Start-Process -FilePath rundll32 -ArgumentList "printui.dll,PrintUIEntry /in /n $($GlobalPrinter) /q"
}
if ($prefs.FunctionExecution.ScheduledTaskLaunch) {
    InvokeScheduledTasks($ScheduledTaskList, [ref]$Logger)
}
if ($prefs.FunctionExecution.PrinterRemoval) {
    RemovePrinters($(,$InvalidPrintServers), $(,$InvalidPrinterNames), [ref]$Logger)
}
if ($prefs.FunctionExecution.ProcessLaunch) {
    LaunchProcesses($ProcessList, [ref]$Logger)
}
foreach ($task in $prefs.OneTimeTasks) {
    $Now = [DateTime]::Now
    $RunTime = $Now.AddMinutes($task.Delay)
    $ExpTime = $RunTime.AddMinutes($task.Expiry)
    $TaskTrigger = New-ScheduledTaskTrigger -Once -At $RunTime
    $TaskTrigger.EndBoundary = $ExpTime.ToString("yyyy-MM-dd'T'HH:mm:ss")
    $TaskSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:00:01 -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -Hidden
    $TaskAction = New-ScheduledTaskAction -Execute $task.TaskPath
    try {
        $null = Register-ScheduledTask -TaskName $task.TaskName -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -ErrorAction SilentlyContinue
        $Logger.Log("OneTimeTasks: Task registration complete - $($task.TaskName)")
    } catch {
        $Logger.Log('OneTimeTasks: Task registration failed.')
    }
}

if ($prefs.FunctionExecution.TipOfTheDay -and -not $prefs.FunctionExecution.NewTotd) {
    Show-Totd($TotdBasePath, [ref]$Logger)
} elseif ($prefs.FunctionExecution.NewTotd) {
    Show-NewTotd($DatabaseServer, $TotdDatabase, $TotdImage, $TotdXaml, [ref]$Logger)
}
if ($prefs.FunctionExecution.SafetyTip) {
    Show-NewTotd($DatabaseServer, $SafetyDatabase, $TotdImage, $SafetyXaml, [ref]$Logger)
}
if ($prefs.FunctionExecution.Logging -or $prefs.FunctionExecution.HardwareInventory) {
    Update-LogCache([ref]$eudLogger)
}
if ($prefs.LoggingOverrides.LogDebugData -or $debug) {
    $fileName = "$($env:USERNAME).txt"
    $Logger.LogFile = [System.IO.Path]::Combine($prefs.FileVariables.DebugLogLoc, $filename)
    $Logger.WriteLogFile()
}

$eudLogger.Dispose()

# Each function that uses the connection should open and close the connection independently, but this is good housekeeping
# To ensure dangling connections aren't left
if ($connection) {
    CloseSQLConnection($connection, [ref]$Logger)
}

exit

# General exception trap to close the $connection if it exists
trap {
    $Logger.Log("Global: General uncaught error. $($_)")
    if ($connection -and ($connection.State -ne [System.Data.ConnectionState]::Closed)) {
        $connection.Close()
    }
    continue
}