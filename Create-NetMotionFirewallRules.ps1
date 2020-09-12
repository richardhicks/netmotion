<#

.SYNOPSIS
    Creates firewall rules required for NetMotion Mobility and Mobile IQ infrastructure servers.

.PARAMETER DualNic
    Use this parameter if the NetMotion connection server is configured with two network interfaces.

.PARAMETER SmallDeploymentServer
    Use this parameter if the NetMotion server is deployed using the Small Deployment Server option.

.PARAMETER ConnectionServer
    Use this parameter if the NetMotion server is configured as a connection server.

.PARAMETER WarehouseServer
    Use this parameter if the NetMotion server is configured as a warehouse server.

.PARAMETER AnalyticsServer
    Use this parameter if the NetMotion server is configured as an analytics server.

.PARAMETER PublisherServer
    Use this parameter if the NetMotion server is configured as a publisher server.

.PARAMETER MobileIQServer
    Use this parameter if the NetMotion server is configured as a Mobile IQ server.

.PARAMETER EnhancedSecurity
    Use this parameter to perform firewall hardening for dual-NIC connection server deployments.

.PARAMETER Legacy
    Use this parameter when configuring NetMotion servers prior to version 12.

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -SmallDeploymentServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is configured with a single network interface using the Small Deployment Server option.

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -DualNic -SmallDeploymentServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is configured with a two network interfaces using the Small Deployment Server option.

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -ConnectionServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server it is deployed as a connection server and configured with a single network interface.

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -DualNic -ConnectionServer -EnhancedSecurity

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server it is deployed as a connection server and configured with a single network interface. Also perform additional firewall hardening for dual-NIC deployments.

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -WarehouseServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is deployed as a warehouse server.

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -AnalyticsServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is deployed as an analytics server (v11 or earlier).

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -PublisherServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is deployed as a publisher server (v12 or later).

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -MobileIQServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is deployed as a Mobile IQ server.

.DESCRIPTION
    By default, the NetMotion Mobility and Mobile IQ installer will ask the administrator to disable the Windows firewall during software installation. This is not recommended. Using this PowerShell script allows the administrator to allow NetMotion Mobility and Mobile IQ communication without disabling the Windows firewall.

.LINK
    https://directaccess.richardhicks.com/netmotion/

.NOTES
    Version:        1.3
    Creation Date:  March 11, 2020
    Last Updated:   September 11, 2020
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://directaccess.richardhicks.com/

#>

[CmdletBinding()]

Param(

    [switch]$DualNic,
    [switch]$SmallDeploymentServer,
    [switch]$ConnectionServer,
    [switch]$WarehouseServer,
    [switch]$AnalyticsServer,
    [switch]$PublisherServer,
    [switch]$MobileIQServer,
    [switch]$EnhancedSecurity,
    [switch]$Legacy

)

If ((-Not $SmallDeploymentServer) -and (-Not $ConnectionServer) -and (-Not $WarehouseServer) -and (-Not $AnalyticsServer) -and (-Not $MobileIQServer) -and (-Not $PublisherServer)) {

    Write-Warning 'No deployment configuration specified. Exiting script.'
    Exit

}

If ($DualNic) {

    $SingleNIC = $False

}

Else {

    $SingleNIC = $True

}

# // NetMotion v11.x and earlier uses TCP port 8080 for the web management console. v12 and later uses TCP port 443
If ($Legacy) {

    $WebUiPort = '8080'

}

Else {

    $WebUiPort = '443'

}

# // Create rules for NetMotion connection servers (single NIC)
If (($SingleNic -and $ConnectionServer) -or ($SingleNic -and $SmallDeploymentServer)) {

    Write-Verbose 'Creating NetMotion firewall rules for single-NIC connection server or small deployment server...'
    New-NetFirewallRule -Name 'NmConn-UDP-5008-In' -DisplayName 'NetMotion Connections' -Description 'Allow inbound NetMotion Mobility connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5008 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-UDP-5009-In' -DisplayName 'NetMotion Service (UDP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-TCP-5009-In' -DisplayName 'NetMotion Service (TCP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
   
}

# // Create rules for NetMotion Mobility connection servers (dual NIC)
If (($DualNic -and $ConnectionServer) -or ($DualNic -and $SmallDeploymentServer)) {

    Write-Verbose 'Creating NetMotion firewall rules for dual-NIC connection server or small deployment server...'
    New-NetFirewallRule -Name 'NmConn-UDP-5008-In' -DisplayName 'NetMotion Connections' -Description 'Allow inbound NetMotion Mobility connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5008 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-UDP-5009-In' -DisplayName 'NetMotion Service (UDP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5009 -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-TCP-5009-In' -DisplayName 'NetMotion Service (TCP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

}

# // Create rules for NetMotion analytics and publisher servers
If ($AnalyticsServer -or $PublisherServer) {

    Write-Verbose 'Creating NetMotion firewall rules for analytics or publisher server...'
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmService-TCP-5009-In' -DisplayName 'NetMotion Service' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    If ($AnalyticsServer) {

        New-NetFirewallRule -Name 'NmDatabase-TCP-3306-In' -DisplayName 'NetMotion Analytics Database' -Description 'Allow inbound NetMotion Analytics database connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 3306 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -Name 'NmService-TCP-5673-In' -DisplayName 'NetMotion Analytics Service' -Description 'Allow inbound NetMotion Analytics service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5673 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    }

    Else {

        New-NetFirewallRule -Name 'NmPublisherAlert-TCP-5671-In' -DisplayName 'NetMotion Publisher Alert' -Description 'Allow inbound NetMotion publisher alert connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5671 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -Name 'NmPublisherData-TCP-5672-In' -DisplayName 'NetMotion Publisher Data' -Description 'Allow inbound NetMotion publisher data connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5672 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    }

}

# // Perform firewall hardening for dual-NIC gateway deployments
If ($EnhancedSecurity -and $DualNic) {

    If ($SmallDeploymentServer) {

        Write-Verbose 'Performing firewall hardening for NetMotion dual-NIC small deployment server...'
        Set-NetFirewallRule -DisplayName 'Mobility Warehouse' -Profile Public, Private -Enabled False
        Set-NetFirewallRule -DisplayName 'Mobility Warehouse' -Profile Domain -Enabled True
        Set-NetFirewallRule -DisplayName 'Mobility Warehouse SSL' -Profile Public, Private -Enabled False
        Set-NetFirewallRule -DisplayName 'Mobility Warehouse SSL' -Profile Domain -Enabled True

    }
    
    Write-Verbose 'Performing firewall hardening for NetMotion dual-NIC connection server or small deployment server...'
    Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Profile Public, Private -Enabled False
    Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Profile Public, Private -Enabled False
    Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Profile Domain -Enabled True
    Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Profile Domain -Enabled True

}

# // Clean up default NetMotion warehouse firewall rules
If ($SmallDeploymentServer -or $WarehouseServer) {

    Write-Verbose 'Adding existing NetMotion Warehouse firewall rules to the NetMotion Mobility firewall rule group...'
    $Rule = Get-NetFirewallRule -DisplayName 'Mobility Warehouse'
    $Rule.Group = 'NetMotion Mobility'
    $Rule | Set-NetFirewallRule

    $Rule = Get-NetFirewallRule -DisplayName 'Mobility Warehouse SSL'
    $Rule.Group = 'NetMotion Mobility'
    $Rule | Set-NetFirewallRule

}

# // Clean up default NetMotion Mobile IQ firewall rules
If ($MobileIQServer) {

    Write-Verbose 'Adding existing NetMotion Mobile IQ firewall rules to the NetMotion Mobility firewall rule group...'
    $Rule = Get-NetFirewallRule -DisplayName 'Mobile IQ Console'
    $Rule.Group = 'NetMotion Mobile IQ'
    $Rule | Set-NetFirewallRule

    $Rule = Get-NetFirewallRule -DisplayName 'Mobile IQ HEC'
    $Rule.Group = 'NetMotion Mobile IQ'
    $Rule | Set-NetFirewallRule

}

# SIG # Begin signature block
# MIINbAYJKoZIhvcNAQcCoIINXTCCDVkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSO8Dwq82oU+zf4Aw4dSekF0d
# e2qgggquMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFdjCC
# BF6gAwIBAgIQDOTKENcaCUe5Ct81Y25diDANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTE5MTIxNjAwMDAwMFoXDTIxMTIyMDEyMDAwMFowgbIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1NaXNz
# aW9uIFZpZWpvMSowKAYDVQQKEyFSaWNoYXJkIE0uIEhpY2tzIENvbnN1bHRpbmcs
# IEluYy4xHjAcBgNVBAsTFVByb2Zlc3Npb25hbCBTZXJ2aWNlczEqMCgGA1UEAxMh
# UmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nLCBJbmMuMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAr+wmqY7Bpvs6EmNV227JD5tee0m+ltuYmleTJ1TG
# TCfibcWU+2HOHICHoUdSF4M8L0LoonkIWKoMCUaGFzrvMFjlt/J8juH7kazf3mEd
# Z9lzxOt6GLn5ILpq+8i2xb4cGqLd1k8FEJaFcq66Xvi2xknQ3r8cDJWBXi4+CoLY
# 0/VPNNPho2RTlpN8QL/Xz//hE+KB7YzaF+7wYCVCkR/Qn4D8AfiUBCAw8fNbjNGo
# Q/v7xh+f6TidtC7Y5B8D8AR4IJSok8Zbivz+HJj5wZNWsS70D8HnWQ7hM/7nAwQh
# teh0/kj0m6TMVtsv4b9KCDEyPT71cp5g4JxMO+x3UZh0CQIDAQABo4IBxTCCAcEw
# HwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYEFB6Bcy+o
# ShXw68ntqleXMwE4Lj1jMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
# BQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# c2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUwQzA3BglghkgB
# hv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
# UzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNpZ25pbmdDQS5j
# cnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAcJWSNtlE7Ml9VLf/
# 96z8tVbF05wZ/EkC4O9ouEdg5AmMx/5LdW2Tz4OrwAUCrRWgIRsC2ea4ZzsZli1i
# 7TdwaYmb2LGKMpq0z1g88iyjIdX6jCoUqMQq1jZAFaJ9iMk7Gn2kHrlcHvVjxwYE
# nf3XxMeGkvvBl8CBkV/fPQ2rrSyKeGSdumWdGGx6Dv/OH5log+x6Qdr6tkFC7byK
# oCBsiETUHs63z53QeVjVxH0zXGa9/G57XphUx18UTYkgIobMN4+dRizxA5sU1WCB
# pstchAVbAsM8OhGoxCJlQGjaXxSk6uis2XretUDhNzCodqdz9ul8CVKem9uJTYjo
# V6CBYjGCAigwggIkAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0ECEAzkyhDXGglH
# uQrfNWNuXYgwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGDfcAJ4lPo2CBVj/tVCTU8kXwE1MA0G
# CSqGSIb3DQEBAQUABIIBAIS6zgVkQynIzoNWAHwuJzIrcjsdKCQ3vV+vEJ/FFPz9
# GGda19NeYSRs12w+NlBqIZjfm81/z0m44p+Ex30bYWrAgGF2ZLsb8HyMO1RdrPGW
# wbdNRWkUbyLo7EZ8kerASsDTMmhKes+lk1gXY96LWBfvtEsjwQCDQny+OA2pMsD8
# m39La4O8zpLRpeJD3PW1zM24bBGqM50QWBupLKB9w6FI8THCxLvmTtnGbi+5fGlr
# gC/QFj+84j6eqIdxcJQ/nl7Vj/KMgpxEmpksOUpcGAVwvpbKGk+GYmSJA9xoy8xt
# CVcf+NBwZO+1CwUlS6XsPvunVKKPNGAm2VGKP6mX/XQ=
# SIG # End signature block
