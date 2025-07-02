<#
.SYNOPSIS
    Dashboard for Intune
.DESCRIPTION
    
.NOTES
    Author:     Ed Frost
    Version:    0.5
    To-Do (functionality):
        x-return data to variable
        x-if run recently, do not pull new data
        x    -add force option to force pull new data
        -implement client secret encryption or certificate options
        x-move configuration items into configuration.txt
        x-document all colour choices, maybe provide a swatch?
        -think about branding options
        -make overview dashboard configurable from configuration.txt.
            example:
            rows=3
            row1=cDevsAutopilot,cDevAssigned,cPatNotPatched,cSecNotEncrypted,cComNotCompliant,cUxaRequireAttention,cDevPersonal
            Row2=tPatWindowsReleases,tDevOsVersions,tDevEnrolTypes,tAppApplications
            Row3=vPatTop5Patches,cComComplianceStatus
        x-move functions to external files to dot-source at run-time
        -add parameter for option to backup reporting data
        -add parameter for option to store metrics to track changes over time
        -add option to modify typography for different elements (header, body, etc.)
        -add option to modify header colour
        -add option for favicon
        -documentation & script to set-up service principal with minimum permissions to run this report
            alternatively, this could be run using the user's credentials, but this take away the option of automation
        -documentation on automating this as a dashboard
        -pull from github or a ps repo?
        -MECM options?
            additional requirements for automation
            this would've been good years ago.  I'm leaning towards, no.
    To-Do (data):
        -devices tab: devices by manufacturer totals do not match between chart and table
        -autopilot tab: add tab to show windowsAutopilotDeviceIdentities table
        -devices tab: add ux performance analytics data (startup processes by demand/impact, boot health status, device health)
        -overview tab: add more visual data
        -compliance tab: the compliance data doesn't look right.  some devices have more than one status on the same policy
        -patching tab: will need to pull group membership data to get count of early patching / testing / uat rings
        -devices with wrong name
        -leverage extension attributes to show more data
            -early patch rings
.LINK
    
.EXAMPLE
    New-IntuneDashboard -config c:\path\to\config.txt
#>
[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $config = "C:\Users\x226436\.Code\PS\Intune Dashboard\Configuration.txt",
    [Parameter()]
    [string]
    $scriptRoot = $PSScriptRoot,
    [Parameter()]
    [switch]
    $keepDataAlive,
    [Parameter()]
    [switch]
    $forceDataRetrieval = $false
)

if (-not $scriptRoot) {
    $scriptRoot = $config | Split-Path -Parent
}

# Load configuration variables from the file
Get-Content $config | Where-Object { $_.length -gt 0 -and !$_.StartsWith("#") } | ForEach-Object {
    $var = $_.Split('=', 2).Trim()
    if ($var[1].ToLower() -eq 'true') { $var[1] = $true }
    elseif ($var[1].ToLower() -eq 'false') { $var[1] = $false }
    elseif ($var[1] -match '^\d+$') { $var[1] = [int]$var[1] }
    elseif ($var[1] -match '^\d+\.\d+$') { $var[1] = [double]$var[1] }
    elseif ($var[1] -match '^\d{4}-\d{2}-\d{2}$') { $var[1] = [datetime]$var[1] }
    elseif ($var[1] -match '^\d{2}:\d{2}:\d{2}$') { $var[1] = [timespan]$var[1] }
    elseif ($var[1] -match ',') { $var[1] = $var[1].Split(',').Trim() }
    New-Variable -Scope Script -Name $var[0] -Value $var[1] -Force
    Write-Verbose "Loaded configuration variable: $($var[0]) = $($var[1])" }

if (-not $HTMLPath) {
    $HTMLPath = "$env:TEMP\IntuneDashboard.html"
}

if ($null -ne $managedEnvironment.timestamp -and $forceDataRetrieval -eq $false) {
    [datetime]$dataRetrievalTimeStamp = $managedEnvironment.timestamp
    if ($dataRetrievalTimeStamp -gt (Get-Date).AddHours(-$maxDataAgeInHours)) {
        Write-Output "Environment data has been retrieved recently. Skipping data retrieval."
        $skipDataRetrieval = $true
    }
    else {
        Write-Output "Environment data is older than $maxDataAgeInHours hours. Forcing data retrieval."
        #Remove-Variable managedEnvironment
        $skipDataRetrieval = $false
    }
}

### DOT-SOURCE FUNCTIONS

$functionFiles = Get-ChildItem -Path "$scriptRoot\Functions" -Filter "*.ps1" -File
foreach ($file in $functionFiles) {
    $functionPath = Join-Path -Path $scriptRoot -ChildPath "Functions\$($file.Name)"
    if (Test-Path -Path $functionPath) {
        . $functionPath
    }
    else {
        Write-Warning "Function file '$($file.Name)' not found at path '$functionPath'."
    }
}

### END DOT-SOURCE FUNCTIONS

### RETRIEVE DATA

# get windows release data
$response = ConvertFrom-HtmlTable -Url 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' -Engine AngleSharp
$windowsReleases = $response | ForEach-Object { $_ | Where-Object 'Build' -notlike '' } | Sort-Object 'Availability date' -Descending 
$latestBuilds = $windowsReleases | Where-Object { $_.'Build' -notlike '' -and $_.'Availability date' -ge $(Get-Date -Date (Get-Date).AddDays( - ($minUnpatchedDays)) -Format 'yyyy-MM-dd') } | Sort-Object 'Availability date' -Descending

# get environment data
if (-not $skipDataRetrieval -or $forceDataRetrieval) {
    $managedEnvironment = @{
        timestamp           = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        devices             = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/v1.0/devices'
        users               = $null
        groups              = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/groups?&$filter=onPremisesSyncEnabled+ne+true&$count=true' | Select-Object *, @{n = 'memberCount'; e = { Get-IntunePagedResults -tenantId $tenantId -applicationId $applicationId -clientSecret $clientSecret -appendURL $('/beta/groups/' + $($_.id) + '/transitivemembers/$count') } }

        deviceManagement    = @{
            managedUsers                                           = $null
            managedDevices                                         = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/managedDevices'
            assignedDevices                                        = $null
            deviceCompliancePolicies                               = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/v1.0/deviceManagement/deviceCompliancePolicies'
            windowsAutopilotSettings                               = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/windowsAutopilotSettings'
            windowsAutopilotDeploymentProfiles                     = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/windowsAutopilotDeploymentProfiles'
            windowsAutopilotDeviceIdentities                       = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/windowsAutopilotDeviceIdentities'    
            deviceConfigurations                                   = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/deviceConfigurations'
            userExperienceAnalyticsDeviceScores                    = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/userExperienceAnalyticsDeviceScores'
            userExperienceAnalyticsModelScores                     = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/userExperienceAnalyticsModelScores'
            userExperienceAnalyticsDeviceStartupProcessPerformance = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/userExperienceAnalyticsDeviceStartupProcessPerformance'
            userExperienceAnalyticsDevicePerformance               = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/userExperienceAnalyticsDevicePerformance'
            compliancePolicyStatus                                 = $null
            deviceCompliancePolicyStatus                           = $null 
            osComplianceState                                      = $null
            softwareUpdateRings                                    = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceManagement/deviceConfigurations?$select=id,displayName,lastModifiedDateTime,roleScopeTagIds,microsoft.graph.unsupportedDeviceConfiguration/originalEntityTypeName&$expand=deviceStatusOverview,assignments&$top=120&$filter=isof(%27microsoft.graph.windowsUpdateForBusinessConfiguration%27)&$count=true'
            softwareUpdateRingMembers                              = $null
        }

        deviceAppManagement = @{
            managedAppPolicies      = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/v1.0/deviceAppManagement/managedAppPolicies'
            managedAppRegistrations = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceAppManagement/managedAppRegistrations'
            mobileApps              = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/beta/deviceAppManagement/mobileApps'
        }
    }

    # add patch level to managed devices
    $managedEnvironment.deviceManagement.managedDevices = LeftJoin-Object -LeftObject $($managedEnvironment.deviceManagement.managedDevices | Select-Object *, @{n = 'Build'; e = { $_.osversion.replace('10.0.', '') } }) -RightObject $windowsReleases -On 'Build'\
    $managedEnvironment.deviceManagement.managedDevices = $managedEnvironment.deviceManagement.managedDevices | Select-Object *, @{n = 'featureVersion'; e = { $_.build.split(".")[0] } }, @{n = 'osComplianceState'; e = { if ($_.build -in $latestBuilds.Build) { 'compliant' } else { 'not compliant' } } } 
    $managedEnvironment.deviceManagement.assignedDevices = $managedEnvironment.deviceManagement.managedDevices | Where-Object { $_.autopilotenrolled -eq $true -and $_.userid -ne "" }

    # add update ring data
    $managedEnvironment.deviceManagement.softwareUpdateRingMembers = $managedEnvironment.groups | Where-Object displayName -in $managedEnvironment.deviceManagement.softwareUpdateRings.displayName | ForEach-Object { $thisRing = $_; Get-IntunePagedResults -tenantId $tenantId -applicationId $applicationId -clientSecret $clientSecret -appendURL "/beta/groups/$($_.id)/members" | Select-Object id, displayName, @{n = 'updateRingId'; e = { $thisRing.id } }, @{n = 'updateRingName'; e = { $thisRing.displayName } } }

    $UpdateRingStatusOverview = ($managedEnvironment.deviceManagement.softwareUpdateRingMembers | Group-Object updateRingName | Sort-Object Name | Select-Object `
        @{n = 'Members'; e = { $_.Count } }, 
        @{n = 'Update Ring'; e = { $_.Name } }, 
        @{n = 'Pending'; e = { $managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty pendingCount } }, 
        @{n = 'N/A'; e = { ($managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty notApplicableCount) + ($managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty notApplicablePlatformCount) } }, 
        @{n = 'Success'; e = { $managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty successCount } }, 
        @{n = 'Error'; e = { $managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty errorCount } }, 
        @{n = 'Failed'; e = { $managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty failedCount } }, 
        @{n = 'Conflict'; e = { $managedEnvironment.deviceManagement.softwareUpdateRings | Where-Object displayName -eq $_.Name | Select-Object -ExpandProperty deviceStatusOverview | Select-Object -ExpandProperty conflictCount } }
    )

    # add user data, if enabled
    if ($showUsers) {
        $managedEnvironment.users = get-intunepagedresults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL '/v1.0/users' | Where-Object { $_.mail -notlike '' -and $_.jobtitle -notlike '' -and $_.jobtitle -notlike "-*" }
        $managedEnvironment.deviceManagement.managedUsers = Join -LeftObject $managedEnvironment.deviceManagement.managedDevices -RightObject $managedEnvironment.users -On userPrincipalName -JoinType Inner | Select-Object -Property id, userPrincipalName, displayName, givenName, surname, jobTitle, mail, mobilePhone, businessPhones, officeLocation, preferredLanguage
    }

    # gather compliance policy data
    $managedEnvironment.deviceManagement.compliancePolicyStatus = $managedEnvironment.deviceManagement.deviceCompliancePolicies | ForEach-Object { 
        $thisPolicy = $_
        Get-IntunePagedResults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL "/v1.0/deviceManagement/deviceCompliancePolicies/$($_.id)/deviceStatusOverview" | Select-Object *, @{n = 'Compliance Policy'; e = { $thisPolicy.displayName } }, @{n = 'Description'; e = { $thisPolicy.description } }, @{n = 'Version'; e = { $thisPolicy.version } }
    }

    $managedEnvironment.deviceManagement.deviceCompliancePolicyStatus = $managedEnvironment.deviceManagement.deviceCompliancePolicies | ForEach-Object { 
        $thisPolicy = $_
        Get-IntunePagedResults -tenantId $tenantID -applicationId $applicationId -clientSecret $clientSecret -appendURL "/v1.0/deviceManagement/deviceCompliancePolicies/$($_.id)/deviceStatuses" | Select-Object *, @{n = 'Compliance Policy'; e = { $thisPolicy.displayName } } -ExcludeProperty userName, userPrincipalName -unique
    }

    # add group data
    If ($showGroupMembers) {
        $managedEnvironment.groups = $managedEnvironment.groups | Select-Object *, @{n = 'memberCount'; e = { Get-IntunePagedResults -tenantId $tenantId -applicationId $applicationId -clientSecret $clientSecret -appendURL $('/beta/groups/' + $($_.id) + '/transitivemembers/$count') } }
    }

    if ($excludeThis) {
        # add assignments from patching rings
        [System.Collections.Generic.List[string]]$assignments = @()
        $managedEnvironment.deviceManagement.softwareUpdateRings.assignments.target | Select-Object -Unique groupId | foreach-object {
            $assignments.Add($_.groupId)
        }

        
    }
}
### END RETRIEVE DATA

### BUILD DASHBOARD

# at this time, there is no need for the graph module, as we are using the REST API directly
# Import-Module -Name Microsoft.Graph.Authentication 

$requiredModules = @('PSWriteHTML', 'Dashimo')

$requiredModules | ForEach-Object {
    if (-not (Get-Module -Name $_)) {
        Install-Module -Name $_ 
        Import-Module -Name $_ 
    }
}

Dashboard {

    New-HTMLTabStyle -SlimTabs -BorderRadius 5px -BackgroundColor $colour1 -BackgroundColorActive $colour4 -BackgroundColorActiveTarget $colour5 -LinearGradient -TextColor $colour0
    New-HTMLSectionStyle -HeaderBackGroundColor $colour3 -BackgroundColorContent $colour1 -HeaderTextColor $colour0
    New-HTMLTableStyle -BackgroundColor $colour1 -BorderTopColor $colour2 -TextColor $colour0
    New-ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete #-FontSize 14 -FontFamily 'Segoe UI' -FontWeight normal -GridLineWidth 1px -AxisLineWidth 1px -LegendPosition topRight -LegendFontSize 12px -LegendFontFamily 'Segoe UI' -LegendFontWeight normal
    PanelOption -RemoveShadow

    ### HOME TAB
    Tab -Name '' -IconSolid home {}
    ### OVERVIEW TAB
    Tab -Name 'Overview' -IconSolid binoculars {
        Section -Name 'Overview Numbers' -Invisible -JustifyContent flex-start {
            Section -Name 'Autopilot Devices' {
                $value = $managedEnvironment.deviceManagement.managedDevices | Where-Object autopilotenrolled -eq $true | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold } 
            } 

            Section -Name 'Devices Assigned to Users' {
                $value = $managedEnvironment.deviceManagement.assignedDevices | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold } 
            } 
        
            Section -Name "Not Patched in last $($minUnpatchedDays) days" {
                $value = $managedEnvironment.deviceManagement.assignedDevices | Select-Object serialNumber, autopilotenrolled, userid, osVersion, @{n = 'Build'; e = { $_.osversion.replace('10.0.', '') } } | Where-Object { $_.autopilotenrolled -eq $true -and $_.userid -ne "" -and $_.Build -notin $latestBuilds.Build } | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
            }

            Section -Name 'Not Encrypted' {
                $value = $managedEnvironment.deviceManagement.assignedDevices | Where-Object { $_.autopilotenrolled -eq $true -and $_.userid -ne "" -and $_.isEncrypted -eq $false } | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
            } 

            Section -Name 'Non-Compliant Devices' {
                $value = $managedEnvironment.deviceManagement.assignedDevices | Where-Object { $_.autopilotenrolled -eq $true -and $_.userid -ne "" -and $_.complianceState -eq 'noncompliant' } | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
            }

            Section -Name 'Devices Requiring Attention' {
                $value = $managedEnvironment.deviceManagement.userExperienceAnalyticsDeviceScores | Where-Object { $_.HealthStatus -eq 'needsAttention' } | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
            }

            Section -Name 'Personal Devices' {
                $value = $managedEnvironment.deviceManagement.managedDevices | Where-Object managedDeviceOwnerType -ne 'company' | Measure-Object | Select-Object -ExpandProperty Count
                Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
            }
        }
        Section -Name 'Overview Tables' -CanCollapse -Invisible {
        
            Section -Name 'Windows Releases' {
                $value = $windowsReleases | Select-Object *, @{n = 'KB'; e = { '<a target="_blank" href="https://support.microsoft.com/help/' + $($_.'KB article'.replace('KB', '')) + '">' + $($_.'KB article') + "</a>" } } | Sort-Object 'Availability date' -Descending              
                Table -FixedHeader -HideFooter -DataTable $value -PagingLength $tablePagingLengthS -Buttons $tableButtonLayout -PriorityProperties 'Update type', 'Build', 'Availability date', 'KB' -ExcludeProperty 'Servicing option', 'KB Article' -InvokeHTMLTags
            }

            Section -Name 'OS Version Distribution' {
                Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceManagement.managedDevices | Group-Object osVersion | Sort-Object Count -Descending | Select-Object Count, Name)  -PagingLength $tablePagingLengthS -Buttons $tableButtonLayout
            }

            Section -Name 'Device Enrollment Types' {
                Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceManagement.managedDevices | Group-Object deviceEnrollmentType  | Sort-Object Count -Descending | Select-Object Count, Name)  -PagingLength $tablePagingLengthS -Buttons $tableButtonLayout
            }

            Section -Name 'Applications' {
                Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceAppManagement.mobileApps | Where-Object isAssigned -eq $true | Sort-Object createdDateTime -Descending | Select-Object @{n = 'Application Name'; e = { $_.displayName } }) -PagingLength $tablePagingLengthS -Buttons $tableButtonLayout
            }
        }
    
        Section -Name 'Overview Visuals' -CanCollapse -Invisible {

            Chart -Title 'Top 5 Patch Distribution' -Height 200 {
                ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete
                $data = $managedEnvironment.deviceManagement.managedDevices | Select-Object serialNumber, autopilotenrolled, userid, osVersion, Build, 'Update type', 'KB Article' 
                $data | group-object 'Update type' | where-Object Name -ne '' | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                    New-ChartBar -Name $_.Name -Value $_.Count
                }
            }

            Chart -Title 'Device Compliance Status' -Height 200 {
                ChartBarOptions -Vertical
                ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete 
                $managedEnvironment.deviceManagement.managedDevices | Group-Object complianceState | Sort-Object Count -Descending | ForEach-Object {
                    New-ChartBar -Name $_.Name -Value $_.Count
                }
            }
        }
    }
    ### DEVICES TAB
    if ($showDevices -or $showAll) {
        Tab -Name 'Devices' -IconSolid laptop {
            Section -Name 'Device Summaries' -JustifyContent flex-start -Invisible {
    
                Section -Name 'Autopilot Devices' {
                    $value = $managedEnvironment.deviceManagement.managedDevices | Where-Object autopilotenrolled -eq $true | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold } 
                } 

                Section -Name 'No Group Tag' {
                    $value = $managedEnvironment.deviceManagement.windowsAutopilotDeviceIdentities | Where-Object groupTag -like '' | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name 'Profiles not Assigned' {
                    $value = $managedEnvironment.deviceManagement.windowsAutopilotDeviceIdentities | Where-Object deploymentProfileAssignmentStatus -eq 'notAssigned' | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name 'Devices Assigned to Users' {
                    $value = $managedEnvironment.deviceManagement.assignedDevices | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold } 
                } 

                Section -Name 'Devices Requiring Attention' {
                    $value = $managedEnvironment.deviceManagement.userExperienceAnalyticsDeviceScores | Where-Object { $_.HealthStatus -eq 'needsAttention' } | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name "Incorrect Device Names" {
                    $value = $managedEnvironment.deviceManagement.assignedDevices | Where-Object { $_.deviceName -ne $_.serialNumber } | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name "Low Disk Space (< $($minFreeDisk))" {
                    $value = $($managedEnvironment.deviceManagement.managedDevices | Where-Object { $_.autopilotenrolled -eq $true -and $_.userid -ne "" -and $_.freeStorageSpaceInBytes -lt $($minFreeDisk / 1) } | Measure-Object | Select-Object -ExpandProperty Count) 
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }
            }

            Section -Name 'Device Visuals' -CanCollapse -Invisible {
                Section -Name 'Devices by Manufacturer' {
                    Chart -Height 200 {
                        #ChartLegend -Names 'Success', 'Error', 'Failed', 'Pending' -LegendPosition bottom
                        ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete
                        #ChartBarOptions $ -Distributed
                        $managedEnvironment.deviceManagement.managedDevices | Group-Object Manufacturer | Where-Object { $_.Name -ne '' -and $_.count -ge 10 } | Sort-Object Count -Descending | Select-Object Count, @{n = 'Manufacturer'; e = { ($_.name).Split(" ")[0] } } | ForEach-Object {
                            ChartBar -Name $_.Manufacturer -Value $_.count
                        }
                    }
                } 
            }

            Section -Name 'Devices' -CanCollapse -Invisible {
                Section -Name 'Managed Devices' -Invisible {
                    Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceManagement.assignedDevices | Sort-Object lastSyncDateTime -Descending | Select-Object deviceName, osVersion, manufacturer, model, autopilotEnrolled, complianceState, complianceGracePeriodExpirationDateTime, aadRegistered, enrolledDateTime, enrollmentProfileName, enrolledByUserPrincipalName, isEncrypted, serialNumber, operatingSystem, skuFamily, skuNumber, userDisplayName, userId, userPrincipalName, usersLoggedOn, activationLockBypassCode, androidSecurityPatchLevel, azureActiveDirectoryDeviceId, azureADDeviceId, azureADRegistered, bootstrapTokenEscrowed, chassisType, chromeOSDeviceInfo, configurationManagerClientEnabledFeatures, configurationManagerClientHealthState, configurationManagerClientInformation, deviceActionResults, deviceCategoryDisplayName, deviceEnrollmentType, deviceFirmwareConfigurationInterfaceManaged, deviceHealthAttestationState, deviceIdentityAttestationDetail, deviceRegistrationState, deviceType, easActivated, easActivationDateTime, easDeviceId, emailAddress, ethernetMacAddress, exchangeAccessState, exchangeAccessStateReason, exchangeLastSuccessfulSyncDateTime, freeStorageSpaceInBytes, hardwareInformation, iccid, id, imei, isSupervised, jailBroken, joinType, lastSyncDateTime, lostModeState, managedDeviceName, managedDeviceOwnerType, managementAgent, managementCertificateExpirationDate, managementFeatures, managementState, meid, notes, ownerType, partnerReportedThreatState, phoneNumber, physicalMemoryInBytes, preferMdmOverGroupPolicyAppliedDateTime, processorArchitecture, remoteAssistanceSessionErrorDetails, remoteAssistanceSessionUrl, requireUserEnrollmentApproval, retireAfterDateTime, roleScopeTagIds, securityPatchLevel, specificationVersion, subscriberCarrier, supplementalDeviceDetails, totalStorageSpaceInBytes, udid, wiFiMacAddress, windowsActiveMalwareCount, windowsRemediatedMalwareCount) -PagingLength $tablePagingLengthM -Buttons $($tableButtonLayout + 'pageLength') {
                        New-TableRowGrouping -Name 'manufacturer' -Color $colour5 -BackgroundColor $colour4 
                    }
                }
            }
        }
    }
    ### USERS TAB
    if ($showUsers -or $showAll) {
        Tab -Name 'Users' -IconSolid user {
            Section -Name 'Users' -CanCollapse -Invisible {
                Section -Name 'Users' -Invisible {
                    Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceManagement.managedUsers | Sort-Object surname ) -PriorityProperties surname, givenName, jobTitle, userPrincipalName, displayName, mail, mobilePhone -ExcludeProperty id, businessPhones -PagingLength $tablePagingLengthM -Buttons $($tableButtonLayout + 'pageLength') -AlphabetSearch
                }
            }
        }
    }
    ### COMPLIANCE TAB
    if ($showCompliance -or $showAll) {
        Tab -Name 'Compliance' -IconSolid clipboard-check {

            Section -Name 'Compliance Policy Summary' -JustifyContent flex-end -CanCollapse -Invisible {
                $managedEnvironment.deviceManagement.compliancePolicyStatus | ForEach-Object { 
                    Section -Name $($_.'Compliance Policy') {
                        Chart -Height 200 {
                            ChartLegend -Names 'Success', 'Error', 'Failed', 'Pending' -LegendPosition bottom
                            ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete
                            if ($_.successCount -gt 0) { New-ChartDonut -Name "Success" -Value $_.successCount }
                            if ($_.errorCount -gt 0) { New-ChartDonut -Name "Error" -Value $_.errorCount }
                            if ($_.pendingCount -gt 0) { New-ChartDonut -Name "Pending" -Value $_.pendingCount }
                        }
                    }
                }

                Section -Name 'Device Compliance Status Rate by Policy' {
                    $data = $managedEnvironment.deviceManagement.compliancePolicyStatus | ForEach-Object {
                        $($_ | Select-Object @{n = 'Compliance Policy'; e = { $_.'Compliance Policy' } }, @{n = 'Version'; e = { $_.version } }, @{n = 'Last Update'; e = { $_.lastUpdateDateTime } }, @{n = 'Statuses'; e = { $($_.pendingCount + $_.errorCount + $_.failedCount + $_.successCount + $_.notApplicableCount) } }, @{n = 'Rate'; e = { $(($_.pendingCount + $_.errorCount + $_.failedCount + $_.successCount + $_.notApplicableCount) / $managedEnvironment.deviceManagement.managedDevices.count).ToString('P0') } })
                    }
                
                    Table -HideFooter -DisableInfo -DataTable $data -Buttons $tableButtonLayout -DisableSearch -DisablePaging -PriorityProperties 'Compliance Policy', 'Statuses', 'Rate', 'Version', 'Last Update'
                }
            }

            Section -Name 'Compliance Data Table' -Invisible {
                Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceManagement.deviceCompliancePolicyStatus) -PagingLength $tablePagingLengthM -Buttons $($tableButtonLayout + 'pageLength') -PriorityProperties 'Compliance Policy', 'deviceDisplayName', 'status', 'lastReportedDateTime' -ExcludeProperty id {
                    New-TableRowGrouping -Name 'Compliance Policy' -Color $colour5 -BackgroundColor $colour4 
                }
            }
        }
    }
    ### PATCHING TAB
    if ($showPatching -or $showAll) {
        Tab -Name 'Patching' -IconSolid shield-alt {
            Section -Name 'Patching Numbers' -Invisible -JustifyContent flex-start {
                Section -Name "Compliance ($($minUnpatchedDays) days)" {
                    $value = $( ($managedEnvironment.deviceManagement.assignedDevices | Where-Object Build -in $latestBuilds.Build | Measure-Object | Select-Object -ExpandProperty Count) / ($managedEnvironment.deviceManagement.assignedDevices | Measure-Object | Select-Object -ExpandProperty Count)).ToString('P0')
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name "Not Patched in last $($minUnpatchedDays) days" {
                    $value = $managedEnvironment.deviceManagement.assignedDevices | Where-Object { $_.autopilotenrolled -eq $true -and $_.userid -ne "" -and $_.Build -notin $latestBuilds.Build } | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name "Failed Patch Deployments" {
                    $value = $updateRingStatusOverview | Measure-Object -Property Failed | Select-Object -ExpandProperty Sum
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }
            
                Section -Name "Early Patching Ring" {
                    $value = $managedEnvironment.deviceManagement.softwareUpdateRingMembers | Where-Object updateRingName -in $earlyRing | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name "Testing Ring" {
                    $value = $managedEnvironment.deviceManagement.softwareUpdateRingMembers | Where-Object updateRingName -in $testRing | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }

                Section -Name "Pilot Ring" {
                    $value = $managedEnvironment.deviceManagement.softwareUpdateRingMembers | Where-Object updateRingName -in $pilotRing | Measure-Object | Select-Object -ExpandProperty Count
                    Panel -AlignContentText center { New-HTMLText -Text $value -FontSize 36 -FontWeight bold }
                }
            }

            Section -Name 'Patching Tables' -CanCollapse -Invisible -JustifyContent flex-end {
                Section -Name 'Devices by OS Version' {
                    $data = $($managedEnvironment.deviceManagement.assignedDevices | Group-Object osVersion | Sort-Object Count -Descending | foreach-object {
                            $thisCount = $_.Count 
                            $managedEnvironment.deviceManagement.assignedDevices | Where-Object osVersion -eq $_.Name | Select-Object -Unique @{n = 'Count'; e = { $thisCount } }, osVersion, 'Servicing option', 'Update Type', 'Availability date', @{n = 'KB'; e = { '<a target="_blank" href="https://support.microsoft.com/help/' + $($_.'KB article'.replace('KB', '')) + '">' + $($_.'KB article') + "</a>" } }
                        })
                    Table -FixedHeader -HideFooter -DataTable $data -InvokeHTMLTags -PagingLength $tablePagingLengthS -Buttons $tableButtonLayout -PriorityProperties Count, 'Update type', 'osVersion', 'KB', 'Availability date'
                }

                Section -Name 'Update Rings' {
                    $data = $UpdateRingStatusOverview
                    Table -FixedHeader -HideFooter -DataTable $data -InvokeHTMLTags -PagingLength $tablePagingLengthS -Buttons $tableButtonLayout -PriorityProperties 'Update Ring', Members, 'Pending', 'N/A', 'Success', 'Error', 'Failed', 'Conflict' -ExcludeProperty id, updateRingId, updateRingName 
                }
            }

            Panel {
                Section -Name 'Feature Version Compliance' {
                    [System.Collections.Generic.list[psobject]]$featureVerCompliance = @()
                    $featureVersions = $managedEnvironment.deviceManagement.assignedDevices | Select-Object build, @{n = 'featureVersion'; e = { $_.build.split(".")[0] } } | Group-Object featureVersion 
                    $featureVersions | ForEach-Object {
                        $thisVersion = $_
                        $thisCompliant = $managedEnvironment.deviceManagement.assignedDevices | Where-Object { $_.featureVersion -eq $thisVersion.Name -and $_.osComplianceState -eq 'compliant' } | Measure-Object | Select-Object -ExpandProperty count
                        $featureVerCompliance.Add( $($thisVersion | Select-Object @{n = 'featureVersion'; e = { $_.Name } }, @{n = 'Compliant'; e = { $thisCompliant } }, @{n = 'Not Compliant'; e = { $thisVersion.Count - $thisCompliant } }, @{n = 'Total'; e = { $thisVersion.Count } }) )
                    }

                    #Chart -Height 150 {
                    #    ChartBarOptions -Type barStacked100Percent
                    #    ChartLegend -Names 'Compliant', 'Not Compliant' -LegendPosition bottom 
                    #    ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete 
                    #    $featureVerCompliance | ForEach-Object {
                    #        New-ChartBar -Name $_.featureVersion -Value @($_.Compliant, $_.'Not Compliant') -Color @($colour4, $colour3)
                    #    }
                    #}

                    $featureVerCompliance | ForEach-Object { 
                        Panel {
                            Chart -Height 200 -Title $_.featureVersion -TitleAlignment center {
                                ChartLegend -Names 'Compliant', 'Not Compliant' -LegendPosition bottom
                                ChartTheme -Color $colour4 -ShadeTo light -Palette $chartPallete
                                if ($_.Compliant -gt 0) { New-ChartDonut -Name "Compliant" -Value $_.Compliant -Color $colour4 }
                                if ($_.'Not Compliant' -gt 0) { New-ChartDonut -Name "Not Compliant" -Value $_.'Not Compliant' -Color $colour3 }
                            }
                        }
                    }
                }
            }

            Section -Name 'Patching Data Table' -Invisible {
                Table -FixedHeader -HideFooter -DataTable $($managedEnvironment.deviceManagement.assignedDevices | Select-Object *, @{n = 'WUfB Enabled'; e = { $_.configurationManagerClientEnabledFeatures.windowsUpdateForBusiness } } | Sort-Object osVersion -Descending | Where-Object osVersion -gt 0) -PagingLength $tablePagingLengthM -Buttons $($tableButtonLayout + 'pageLength') -PriorityProperties deviceName, autopilotEnrolled, 'WUfB Enabled', build, operatingSystem, skuFamily, 'Update type', 'KB Article', userDisplayName, emailAddress, serialNumber, managementAgent, lastSyncDateTime -ExcludeProperty id, userid {
                    New-TableRowGrouping -Name 'osVersion' -Color $colour5 -BackgroundColor $colour4 
                }
            }
        }
    }

    ### START TEST HTML
    <#
    New-HTML -TitleText "Test" {
        Dashboard {
            Tab -Name 'Test' -IconSolid home {
                Section -Name 'Test' -CanCollapse -Invisible {
                    $featureVerCompliance | ForEach-Object {
                            New-ChartRadial -Name $_.featureVersion -Value @($_.Compliant, $_.'Not Compliant') -Color @($colour4, $colour3) -Label $_.featureVersion
                        }
                }
            }
        }   
    } -ShowHTML:$true 
    #>
    ### END TEST HTML  

} -ShowHTML:$showHTML -FilePath $HTMLPath -TitleText $dashboardTitle -Author $dashboardAuthor -AutoRefresh:$autoRefresh -Online 

Write-Output "Dashboard has been generated and saved to $HTMLPath."

# If the keepDataAlive switch is set, store the managedEnvironment data in a global variable
# This allows further processing or use in other scripts without needing to re-fetch the data.
if ($keepDataAlive) {
    Write-Output "Data has been kept alive for further processing. Variable 'managedEnvironment' is available in the global scope."
    $global:managedEnvironment = $managedEnvironment
}