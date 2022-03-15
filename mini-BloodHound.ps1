# Picked the rules from SharpHoundCommon lib

# Only for powershell 2.0. For more detail, you can check this repository.
# - https://github.com/EliteLoser/ConvertTo-Json
# For collector main function, please goto line 308.
function EscapeJson {
    param(
        [String] $String)
    # removed: #-replace '/', '\/' `
    # This is returned 
    $String -replace '\\', '\\' -replace '\n', '\n' `
        -replace '\u0008', '\b' -replace '\u000C', '\f' -replace '\r', '\r' `
        -replace '\t', '\t' -replace '"', '\"'
}

function GetNumberOrString {
    param(
        $InputObject)
    if ($InputObject -is [System.Byte] -or $InputObject -is [System.Int32] -or `
        ($env:PROCESSOR_ARCHITECTURE -imatch '^(?:amd64|ia64)$' -and $InputObject -is [System.Int64]) -or `
        $InputObject -is [System.Decimal] -or `
        ($InputObject -is [System.Double] -and -not [System.Double]::IsNaN($InputObject) -and -not [System.Double]::IsInfinity($InputObject)) -or `
        $InputObject -is [System.Single] -or $InputObject -is [long] -or `
        ($Script:CoerceNumberStrings -and $InputObject -match $Script:NumberRegex)) {
        Write-Verbose -Message "Got a number as end value."
        "$InputObject"
    }
    else {
        Write-Verbose -Message "Got a string (or 'NaN') as end value."
        """$(EscapeJson -String $InputObject)"""
    }
}

function ConvertToJsonInternal {
    param(
        $InputObject, # no type for a reason
        [Int32] $WhiteSpacePad = 0)
    
    [String] $Json = ""
    
    $Keys = @()
    
    Write-Verbose -Message "WhiteSpacePad: $WhiteSpacePad."
    
    if ($null -eq $InputObject) {
        Write-Verbose -Message "Got 'null' in `$InputObject in inner function"
        $null
    }
    
    elseif ($InputObject -is [Bool] -and $InputObject -eq $true) {
        Write-Verbose -Message "Got 'true' in `$InputObject in inner function"
        $true
    }
    
    elseif ($InputObject -is [Bool] -and $InputObject -eq $false) {
        Write-Verbose -Message "Got 'false' in `$InputObject in inner function"
        $false
    }
    
    elseif ($InputObject -is [DateTime] -and $Script:DateTimeAsISO8601) {
        Write-Verbose -Message "Got a DateTime and will format it as ISO 8601."
        """$($InputObject.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"""
    }
    
    elseif ($InputObject -is [HashTable]) {
        $Keys = @($InputObject.Keys)
        Write-Verbose -Message "Input object is a hash table (keys: $($Keys -join ', '))."
    }
    
    elseif ($InputObject.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
        $Keys = @(Get-Member -InputObject $InputObject -MemberType NoteProperty |
            Select-Object -ExpandProperty Name)

        Write-Verbose -Message "Input object is a custom PowerShell object (properties: $($Keys -join ', '))."
    }
    
    elseif ($InputObject.GetType().Name -match '\[\]|Array') {
        
        Write-Verbose -Message "Input object appears to be of a collection/array type. Building JSON for array input object."
        
        $Json += "[`n" + (($InputObject | ForEach-Object {
            
            if ($null -eq $_) {
                Write-Verbose -Message "Got null inside array."

                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "null"
            }
            
            elseif ($_ -is [Bool] -and $_ -eq $true) {
                Write-Verbose -Message "Got 'true' inside array."

                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "true"
            }
            
            elseif ($_ -is [Bool] -and $_ -eq $false) {
                Write-Verbose -Message "Got 'false' inside array."

                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "false"
            }
            
            elseif ($_ -is [DateTime] -and $Script:DateTimeAsISO8601) {
                Write-Verbose -Message "Got a DateTime and will format it as ISO 8601."

                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$($_.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"""
            }
            
            elseif ($_ -is [HashTable] -or $_.GetType().FullName -eq "System.Management.Automation.PSCustomObject" -or $_.GetType().Name -match '\[\]|Array') {
                Write-Verbose -Message "Found array, hash table or custom PowerShell object inside array."

                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + (ConvertToJsonInternal -InputObject $_ -WhiteSpacePad ($WhiteSpacePad + 4)) -replace '\s*,\s*$'
            }
            
            else {
                Write-Verbose -Message "Got a number or string inside array."

                $TempJsonString = GetNumberOrString -InputObject $_
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + $TempJsonString
            }

        }) -join ",`n") + "`n$(" " * (4 * ($WhiteSpacePad / 4)))],`n"

    }
    else {
        Write-Verbose -Message "Input object is a single element (treated as string/number)."

        GetNumberOrString -InputObject $InputObject
    }
    if ($Keys.Count) {

        Write-Verbose -Message "Building JSON for hash table or custom PowerShell object."

        $Json += "{`n"

        foreach ($Key in $Keys) {

            # -is [PSCustomObject]) { # this was buggy with calculated properties, the value was thought to be PSCustomObject

            if ($null -eq $InputObject.$Key) {
                Write-Verbose -Message "Got null as `$InputObject.`$Key in inner hash or PS object."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": null,`n"
            }

            elseif ($InputObject.$Key -is [Bool] -and $InputObject.$Key -eq $true) {
                Write-Verbose -Message "Got 'true' in `$InputObject.`$Key in inner hash or PS object."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": true,`n"            }

            elseif ($InputObject.$Key -is [Bool] -and $InputObject.$Key -eq $false) {
                Write-Verbose -Message "Got 'false' in `$InputObject.`$Key in inner hash or PS object."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": false,`n"
            }

            elseif ($InputObject.$Key -is [DateTime] -and $Script:DateTimeAsISO8601) {
                Write-Verbose -Message "Got a DateTime and will format it as ISO 8601."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": ""$($InputObject.$Key.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"",`n"
                
            }

            elseif ($InputObject.$Key -is [HashTable] -or $InputObject.$Key.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
                Write-Verbose -Message "Input object's value for key '$Key' is a hash table or custom PowerShell object."
                $Json += " " * ($WhiteSpacePad + 4) + """$Key"":`n$(" " * ($WhiteSpacePad + 4))"
                $Json += ConvertToJsonInternal -InputObject $InputObject.$Key -WhiteSpacePad ($WhiteSpacePad + 4)
            }

            elseif ($InputObject.$Key.GetType().Name -match '\[\]|Array') {

                Write-Verbose -Message "Input object's value for key '$Key' has a type that appears to be a collection/array."
                Write-Verbose -Message "Building JSON for ${Key}'s array value."

                $Json += " " * ($WhiteSpacePad + 4) + """$Key"":`n$(" " * ((4 * ($WhiteSpacePad / 4)) + 4))[`n" + (($InputObject.$Key | ForEach-Object {

                    if ($null -eq $_) {
                        Write-Verbose -Message "Got null inside array inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "null"
                    }

                    elseif ($_ -is [Bool] -and $_ -eq $true) {
                        Write-Verbose -Message "Got 'true' inside array inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "true"
                    }

                    elseif ($_ -is [Bool] -and $_ -eq $false) {
                        Write-Verbose -Message "Got 'false' inside array inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "false"
                    }

                    elseif ($_ -is [DateTime] -and $Script:DateTimeAsISO8601) {
                        Write-Verbose -Message "Got a DateTime and will format it as ISO 8601."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + """$($_.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"""
                    }

                    elseif ($_ -is [HashTable] -or $_.GetType().FullName -eq "System.Management.Automation.PSCustomObject" `
                        -or $_.GetType().Name -match '\[\]|Array') {
                        Write-Verbose -Message "Found array, hash table or custom PowerShell object inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + (ConvertToJsonInternal -InputObject $_ -WhiteSpacePad ($WhiteSpacePad + 8)) -replace '\s*,\s*$'
                    }

                    else {
                        Write-Verbose -Message "Got a string or number inside inside array."
                        $TempJsonString = GetNumberOrString -InputObject $_
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + $TempJsonString
                    }

                }) -join ",`n") + "`n$(" " * (4 * ($WhiteSpacePad / 4) + 4 ))],`n"

            }
            else {

                Write-Verbose -Message "Got a string inside inside hashtable or PSObject."
                # '\\(?!["/bfnrt]|u[0-9a-f]{4})'

                $TempJsonString = GetNumberOrString -InputObject $InputObject.$Key
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": $TempJsonString,`n"

            }

        }

        $Json = $Json -replace '\s*,$' # remove trailing comma that'll break syntax
        $Json += "`n" + " " * $WhiteSpacePad + "},`n"

    }

    $Json

}

function ConvertTo-STJson {
    [CmdletBinding()]
    #[OutputType([Void], [Bool], [String])]
    Param(
        [AllowNull()]
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        $InputObject,
        [Switch] $Compress,
        [Switch] $CoerceNumberStrings = $False,
        [Switch] $DateTimeAsISO8601 = $False)
    Begin{

        $JsonOutput = ""
        $Collection = @()
        # Not optimal, but the easiest now.
        [Bool] $Script:CoerceNumberStrings = $CoerceNumberStrings
        [Bool] $Script:DateTimeAsISO8601 = $DateTimeAsISO8601
        [String] $Script:NumberRegex = '^-?\d+(?:(?:\.\d+)?(?:e[+\-]?\d+)?)?$'
        #$Script:NumberAndValueRegex = '^-?\d+(?:(?:\.\d+)?(?:e[+\-]?\d+)?)?$|^(?:true|false|null)$'

    }

    Process {

        # Hacking on pipeline support ...
        if ($_) {
            Write-Verbose -Message "Adding object to `$Collection. Type of object: $($_.GetType().FullName)."
            $Collection += $_
        }

    }

    End {
        
        if ($Collection.Count) {
            Write-Verbose -Message "Collection count: $($Collection.Count), type of first object: $($Collection[0].GetType().FullName)."
            $JsonOutput = ConvertToJsonInternal -InputObject ($Collection | ForEach-Object { $_ })
        }
        
        else {
            $JsonOutput = ConvertToJsonInternal -InputObject $InputObject
        }
        
        if ($null -eq $JsonOutput) {
            Write-Verbose -Message "Returning `$null."
            return $null # becomes an empty string :/
        }
        
        elseif ($JsonOutput -is [Bool] -and $JsonOutput -eq $true) {
            Write-Verbose -Message "Returning `$true."
            [Bool] $true # doesn't preserve bool type :/ but works for comparisons against $true
        }
        
        elseif ($JsonOutput-is [Bool] -and $JsonOutput -eq $false) {
            Write-Verbose -Message "Returning `$false."
            [Bool] $false # doesn't preserve bool type :/ but works for comparisons against $false
        }
        
        elseif ($Compress) {
            Write-Verbose -Message "Compress specified."
            (
                ($JsonOutput -split "\n" | Where-Object { $_ -match '\S' }) -join "`n" `
                    -replace '^\s*|\s*,\s*$' -replace '\ *\]\ *$', ']'
            ) -replace ( # these next lines compress ...
                '(?m)^\s*("(?:\\"|[^"])+"): ((?:"(?:\\"|[^"])+")|(?:null|true|false|(?:' + `
                    $Script:NumberRegex.Trim('^$') + `
                    ')))\s*(?<Comma>,)?\s*$'), "`${1}:`${2}`${Comma}`n" `
              -replace '(?m)^\s*|\s*\z|[\r\n]+'
        }
        
        else {
            ($JsonOutput -split "\n" | Where-Object { $_ -match '\S' }) -join "`n" `
                -replace '^\s*|\s*,\s*$' -replace '\ *\]\ *$', ']'
        }
    
    }

}

# Main function
function Invoke-mini
{
    #Check existed function
    $oriCompress = $false
    if (Get-Command 'Compress-Archive' -errorAction SilentlyContinue){
        Write-Output "[+] Original compress function is existed, using it."
        $oriCompress = $true
    }else{
        Write-Output "[-] Original compress function is not existed, using custom compress function."
        $oriCompress = $false
    }
    
    # Main
    $Date = Get-Date -UFormat %Y%m%d%H%M%S
    $fileName = "$($Date)_mini-BloodHound"
    $collections = @{
        #"AllObjects"="(objectclass=*)"
        "AllUsers"="(samaccounttype=805306368)"
        "AllGroups"="|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)"
        "AllPrimaryGroups"="(primarygroupid=*)"
        "AllGPOs"="&(objectcategory=groupPolicyContainer)(flags=*)"
        "AllOUs"="(objectcategory=organizationalUnit)"
        "AllDomains"="(objectclass=domain)"
        "AllContainers"="(objectClass=container)"
        "AllComputers"="(samaccounttype=805306369)"
        "AllSchemaID"="(schemaidguid=*)"
    }
    foreach ($collectObject in $collections.keys) {
        #write-output "[+] Currenct collection object: $collectObject value: $($collections[$collectObject])"
        $searcher=[adsisearcher]"($($collections[$collectObject]))"
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | foreach {$_.GetDirectoryEntry()}
        
        #I want to use SecurityMasks to get Aces, but it seen it did not work on windows 2008
        #SecurityMasks seens only work on > 2008/win7
        #$searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
	    
        #searcher.PageSize = 10000
        #This probably will spend a long time in a large scale AD XD
        $searcher.SearchRoot = $currentDomain
        $searcher.PageSize = 2147483647
        $searcher.SearchScope = "Subtree"
        $results=$searcher.FindAll()

        if($results){ 
            write-output "[+] Got object: $collectObject from active directory succeed !"
            $tempList = [System.Collections.ArrayList]@()
            $num = $results.count
            foreach($i in 0..$($num - 1)){
                $single = $results[$i]
                foreach ( $a in $single.properties){
                    $tempDict = @{}
                    $Name = $a | Format-Table Name -HideTableHeaders | Out-String
                    foreach ($tag in $Name.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)){
                        # Backup condition: ($tag.Trim() -ne "ntsecuritydescriptor") -and ($tag.Trim() -ne "usercertificate") -and ($tag.Trim() -inotmatch "msexch")
                        # I think exclude object is better than $searcher.propertiestoload.add function
                        $Key = $($tag.Trim())
                        if (($Key -ne "usercertificate") -and ($Key -inotmatch "msexch") -and ($Key -ne "msds-managedpasswordid") -and ($Key -ne "ms-ds-creatorsid")){
                            if ($Key -eq "adspath"){
                                # Add adspath
                                $Value = $($single.properties[$Key])
                                $tempDict.Add($Key,$Value)
                                # Use adspath to process Aces
                                $ADobject=[ADSI]"$Value"
                                $Aces = $ADobject.psbase.get_ObjectSecurity().getAccessRules($true, $true, [system.security.principal.NtAccount]) | select-object ActiveDirectoryRights,IsInheritedq,ObjectType,InheritedObjectType,ObjectFlags,AccessControlType,IdentityReference,IsInherited,InheritanceFlags,PropagationFlags
                                $tempDict.Add("Aces",$Aces)
                            } elseif ($key -eq "objectguid"){
                                $rawguid = $single.properties.objectguid[0]
                                $Value = new-object guid(,$rawguid)
                                $tempDict.Add($Key,$Value)
                            } elseif ($key -eq "objectsid"){
                                $rawsid = $single.properties.objectsid[0]
                                $Value = (New-object System.Security.Principal.SecurityIdentifier($rawsid,0)).value
                                $tempDict.Add($Key,$Value)
                            } else{
                                $Value = $($single.properties[$Key])
                                $tempDict.Add($Key,$Value)
                            }
                        }
                    }
                    [void]$tempList.Add($tempDict)
                }
            }
            $tempList | ConvertTo-STJson | set-content -encoding utf8 "$($collectObject).json"
        }
        else{
            write-output "[-] Got object: $collectObject from active directoty failure."
        }
    }
    if ($oriCompress) {
        Compress-Archive -Path "All*.json" -CompressionLevel Fastest -DestinationPath "$($fileName).zip" -Force
    }
    else {
        # For powershell 2.0
        foreach ($file in Get-ChildItem -Path "$(PWD)\All*.json"){
            Add-Content -Path "$(PWD)\$($Date)_temp.txt" -Value "$($file)"
        }
        makecab /f "$(PWD)\$($Date)_temp.txt" /d expresstype=mszip /d expressmemory=21 /d maxdisksize=1024000000 /d diskdirectorytemplate=$(PWD) /d cabinetnametemplate="$($fileName).cab"
        Remove-Item -Path "$($Date)_temp.txt" -Force
    }
    write-output "[+] Compressed all the data files to $($fileName)"
    write-output "[+] Remove useless files"
    Remove-Item -Path "All*.json" -Force
}
Invoke-mini
