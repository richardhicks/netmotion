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

.PARAMETER BandwidthTestServer
    Use this parameter if the NetMotion server is configured as a bandwidth test server.

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

.EXAMPLE
    .\Create-NetMotionFirewallRules.ps1 -BandwidthTestServer

    Run this PowerShell command to create firewall rules to allow NetMotion communication when the server is deployed as a bandwidth test server.

.DESCRIPTION
    By default, the NetMotion Mobility and Mobile IQ installer will ask the administrator to disable the Windows firewall during software installation. This is not recommended. Using this PowerShell script allows the administrator to allow NetMotion Mobility and Mobile IQ communication without disabling the Windows firewall.

.LINK
    https://directaccess.richardhicks.com/netmotion/

.NOTES
    Version:        1.41
    Creation Date:  March 11, 2020
    Last Updated:   December 28, 2021
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
    [switch]$BandwidthTestServer,
    [switch]$Legacy

)

If ((-Not $SmallDeploymentServer) -and (-Not $ConnectionServer) -and (-Not $WarehouseServer) -and (-Not $AnalyticsServer) -and (-Not $MobileIQServer) -and (-Not $PublisherServer) -and (-Not $BandwidthTestServer)) {

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

# // Clean up default NetMotion Bandwidth Test server firewall rules
If ($BandwidthTestServer) {

    Write-Verbose 'Adding existing NetMotion Mobility Bandwidth Server firewall rules to the NetMotion Mobility firewall rule group...'
    $Rule = Get-NetFirewallRule -DisplayName 'Mobility Bandwidth Server'
    $Rule.Group = 'NetMotion Mobility Bandwidth Test'
    $Rule | Set-NetFirewallRule

}

# SIG # Begin signature block
# MIIdWQYJKoZIhvcNAQcCoIIdSjCCHUYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYt4BHmWGkG5KmT40exzEevVw
# U6SgghfxMIIE/jCCA+agAwIBAgIQDUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEw
# NjAwMDAwMFowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMLmYYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQ
# tSYQ/h3Ib5FrDJbnGlxI70Tlv5thzRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4
# bbx9+cdtCT2+anaH6Yq9+IRdHnbJ5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOK
# fF1FLUuxUOZBOjdWhtyTI433UCXoZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlK
# XAwxikqMiMX3MFr5FK8VX2xDSQn9JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYer
# vnpbCiAvSwnJlaeNsvrWY4tOpXIc7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEEGA1UdIAQ6MDgwNgYJYIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAdBgNVHQ4EFgQUNkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0f
# BGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEASBzctemaI7znGucgDo5nRv1CclF0CiNH
# o6uS0iXEcFm+FKDlJ4GlTRQVGQd58NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4
# eTZ6J7fz51Kfk6ftQ55757TdQSKJ+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2h
# F3MN9PNlOXBL85zWenvaDLw9MtAby/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1
# FUL1LTI4gdr0YKK6tFL7XOBhJCVPst/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6X
# t/Q/hOvB46NJofrOp79Wz7pZdmGJX36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZ
# oAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnF
# OVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQA
# OPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhis
# EeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQj
# MF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+f
# MRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW
# /5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAf
# BgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/
# AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYc
# aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafD
# DiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6
# HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4
# H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHK
# eZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIo
# xhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIwggawMIIEmKADAgECAhAIrUCy
# YNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBa
# Fw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc
# 9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyA
# VxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQ
# IXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/
# sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na5
# 9zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pg
# VItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7Bzzosm
# JQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQ
# okbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jL
# chApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHM
# IRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQAB
# o4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8R
# hvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYD
# VR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGsw
# aTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUF
# BzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# Um9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeB
# DAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bg
# Ahql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7
# FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZ
# GM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG
# 3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5U
# bdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WI
# IIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956
# rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuW
# TatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3
# E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60b
# hQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOIm
# YIbqyK+p/pQd52MbOoZWeE4wggcCMIIE6qADAgECAhABZnISBJVCuLLqeeLTB6xE
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjExMjAyMDAwMDAwWhcNMjQx
# MjIwMjM1OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
# FjAUBgNVBAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlj
# a3MgQ29uc3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0
# aW5nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6svrVqBRBbazEkrm
# htz7h05LEBIHp8fGlV19nY2gpBLnkDR8Mz/E9i1cu0sdjieC4D4/WtI4/NeiR5id
# tBgtdek5eieRjPcn8g9Zpl89KIl8NNy1UlOWNV70jzzqZ2CYiP/P5YGZwPy8Lx5r
# IAOYTJM6EFDBvZNti7aRizE7lqVXBDNzyeHhfXYPBxaQV2It+sWqK0saTj0oNA2I
# u9qSYaFQLFH45VpletKp7ded2FFJv2PKmYrzYtax48xzUQq2rRC5BN2/n7771NDf
# J0t8udRhUBqTEI5Z1qzMz4RUVfgmGPT+CaE55NyBnyY6/A2/7KSIsOYOcTgzQhO4
# jLmjTBZ2kZqLCOaqPbSmq/SutMEGHY1MU7xrWUEQinczjUzmbGGw7V87XI9sn8Ec
# WX71PEvI2Gtr1TJfnT9betXDJnt21mukioLsUUpdlRmMbn23or/VHzE6Nv7Kzx+t
# A1sBdWdC3Mkzaw/Mm3X8Wc7ythtXGBcLmBagpMGCCUOk6OJZAgMBAAGjggIGMIIC
# AjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUxF7d
# o+eIG9wnEUVjckZ9MsbZ+4kwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIw
# MjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA+
# BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNB
# NDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
# BQADggIBAEvHt/OKalRysHQdx4CXSOcgoayuFXWNwi/VFcFr2EK37Gq71G4AtdVc
# WNLu+whhYzfCVANBnbTa9vsk515rTM06exz0QuMwyg09mo+VxZ8rqOBHz33xZyCo
# Ttw/+D/SQxiO8uQR0Oisfb1MUHPqDQ69FTNqIQF/RzC2zzUn5agHFULhby8wbjQf
# Ut2FXCRlFULPzvp7/+JS4QAJnKXq5mYLvopWsdkbBn52Kq+ll8efrj1K4iMRhp3a
# 0n2eRLetqKJjOqT335EapydB4AnphH2WMQBHHroh5n/fv37dCCaYaqo9JlFnRIrH
# U7pHBBEpUGfyecFkcKFwsPiHXE1HqQJCPmMbvPdV9ZgtWmuaRD0EQW13JzDyoQdJ
# xQZSXJhDDL+VSFS8SRNPtQFPisZa2IO58d1Cvf5G8iK1RJHN/Qx413lj2JSS1o3w
# gNM3Q5ePFYXcQ0iPxjFYlRYPAaDx8t3olg/tVK8sSpYqFYF99IRqBNixhkyxAyVC
# k6uLBLgwE9egJg1AFoHEdAeabGgT2C0hOyz55PNoDZutZB67G+WN8kGtFYULBloR
# KHJJiFn42bvXfa0Jg1jZ41AAsMc5LUNlqLhIj/RFLinDH9l4Yb0ddD4wQVsIFDVl
# JgDPXA9E1Sn8VKrWE4I0sX4xXUFgjfuVfdcNk9Q+4sJJ1YHYGmwLMYIE0jCCBM4C
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYg
# U0hBMzg0IDIwMjEgQ0ExAhABZnISBJVCuLLqeeLTB6xEMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBTu62u9IitQZMAR+TGqC9ebWPOEajANBgkqhkiG9w0BAQEFAASCAYCYHaW315mn
# sCZRh//dqgtASUkPR5Fa7DCNsHvGGbQJsnIPLksJu9vKipryohbIQLyRLImQhMYa
# v+eLTbl1G359QlCfOdY+FnFNxqmYxUIArNpr1OxQ6BEAZ5YzLtzHYj4cBnZB6bLt
# cZDgOIwOAF7mcbWKKBQVueQ5RA6wQAtJGDqjZ71PNhpCKCvYwIzBuLqnUJCayyzl
# eTgiRZYLHnOy0QA1Af2A2GCekNAc6QiWXcI6dezVowhO4JNSolf+lqYSsKqe6bsw
# 6bcFFRBtfTxViS4Eh40KWmiMXjn3GXlM6EyYui02xe86iiBVN3Tc5FEhARxB3Vm0
# 7ZWmOW7ljxjwKe97D9WFQbHr/LZgGfsmnpv+3HP0nlloqMzjZILmIHj7wH6JTXct
# vN+dh/amKOJ9Wcjg4rCWK961lxLZd8aDI3qtnCOkK3Vygsd4CeeSZCLp4Zw3+gFN
# B2gYS5dq7+paF6XQdslSdEEWv7YDM+qo0Ef8owB0zE+Pv9y3bphZc7KhggIwMIIC
# LAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQ
# DUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMTIyODE5NDMzMlowLwYJKoZI
# hvcNAQkEMSIEIOhOg85DsKWtlpXx7VRO7FNOKL0L7BEUsO/qmQ8SGPQIMA0GCSqG
# SIb3DQEBAQUABIIBAGWz+dsUBjc9b303RZkM9lgFZIwF+H9aILREBznUmI7ObAzG
# Qwd4MpalJqA5Pcd3tcnvqEiqsoe/+bNAb/z1cud7tfnYYIdlhFwdj84ok+kjYcJT
# phNqq31fqy1SX8z1HEyC4AGPc7SjE9m8lMi9Pp3C8JR7+QYLtg7xxVmWkanvMJAZ
# SPv4LjEa1nyJefbtRHT1+tYjz6R3Z5+PC5fmNY2lJHXF4Z0Ge7VPk1dX7Koj6qxy
# +BbxtSVdVFLwMSa3kCnOnT9SJu4TayL7keaDlcs8RpKEYbdjHytPn4tValTzGYlo
# ShnAYdh3TC3k2zE2deHrtoRtksq2gGXMc7kR2/k=
# SIG # End signature block
