<#

.SYNOPSIS
    Creates firewall rules required for NetMotion Mobility and Mobile IQ infrastructure servers.

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

.PARAMETER DualNic
    Use this parameter if the NetMotion connection server is configured with two network interfaces.

.PARAMETER EnhancedSecurity
    Use this parameter to perform firewall hardening for dual-NIC connection server deployments.

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
    The NetMotion Mobility and Mobile IQ installer will, by default, ask the administrator to disable the Windows firewall during software installation. Disabling the Windows firewall is not advisable, however. This PowerShell script enables the administrator to allow NetMotion Mobility and Mobile IQ communication without disabling the Windows firewall.

.LINK
    https://github.com/richardhicks/netmotion/blob/master/Create-NetMotionFirewallRules.ps1

.LINK
    https://directaccess.richardhicks.com/netmotion/

.NOTES
    Version:        1.5
    Creation Date:  March 11, 2020
    Last Updated:   May 27, 2022
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://directaccess.richardhicks.com/

#>

[CmdletBinding()]

Param(

    [switch]$SmallDeploymentServer,
    [switch]$ConnectionServer,
    [switch]$WarehouseServer,
    [switch]$AnalyticsServer,
    [switch]$PublisherServer,
    [switch]$MobileIQServer,
    [switch]$BandwidthTestServer,
    [switch]$DualNic,
    [switch]$EnhancedSecurity

)

If ((-Not $SmallDeploymentServer) -and (-Not $ConnectionServer) -and (-Not $WarehouseServer) -and (-Not $AnalyticsServer) -and (-Not $MobileIQServer) -and (-Not $PublisherServer) -and (-Not $BandwidthTestServer)) {

    Write-Warning 'No deployment configuration specified.'
    Return

}

# // Clean up default NetMotion Mobile IQ firewall rules
If ($MobileIQServer) {

    Write-Verbose 'Adding existing NetMotion Mobile IQ firewall rules to the NetMotion Mobility firewall rule group...'
    $Rules = Get-NetFirewallRule | Where-Object DisplayName -like 'Mobile IQ*'

    Foreach ($Rule in $Rules) {

        $Rule.Group = 'NetMotion Mobile IQ'
        $Rule | Set-NetFirewallRule

    }

    Return

}

# // Clean up default NetMotion bandwidth test server firewall rule
If ($BandwidthTestServer) {

    Write-Verbose 'Adding existing NetMotion Mobility Bandwidth Server firewall rule to the NetMotion Mobility firewall rule group...'
    $Rule = Get-NetFirewallRule -DisplayName 'Mobility Bandwidth Server'
    $Rule.Group = 'NetMotion Mobility'
    $Rule | Set-NetFirewallRule
    Write-Warning 'NetMotion Mobility Bandwidth Server firewall rule configured ONLY. Rerun the script to configure additional roles on this server.'
    Return

}

If ($DualNic) {

    $SingleNIC = $False

}

Else {

    $SingleNIC = $True

}

# // Get NetMotion version
$NmVersion = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\NetMotion\Setup\ -Name ProductVersion -ErrorAction SilentlyContinue

If ($Null -eq $NmVersion) {

    Write-Warning 'Unable to determine NetMotion version.'
    Return

}

Else {

    Write-Verbose "NetMotion version is $NmVersion."

}

# // NetMotion v11.x and earlier uses TCP port 8080 for the web management console. v12 and later uses TCP port 443
If ($NmVersion -lt '12') {

    Write-Verbose 'Setting web management port to 8080...'
    $WebUiPort = '8080'

}

Else {

    Write-Verbose 'Setting web management port to 443...'
    $WebUiPort = '443'

}

# // Create firewall rules for NetMotion connection servers (single NIC)
If (($SingleNic -and $ConnectionServer) -or ($SingleNic -and $SmallDeploymentServer)) {

    Write-Verbose 'Creating NetMotion firewall rules for single-NIC connection server or small deployment server...'
    New-NetFirewallRule -Name 'NmConn-UDP-5008-In' -DisplayName 'NetMotion Connections' -Description 'Allow inbound NetMotion Mobility connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5008 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-UDP-5009-In' -DisplayName 'NetMotion Service (UDP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-TCP-5009-In' -DisplayName 'NetMotion Service (TCP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

}

# // Create firewall rules for NetMotion Mobility connection servers (dual NIC)
If (($DualNic -and $ConnectionServer) -or ($DualNic -and $SmallDeploymentServer)) {

    Write-Verbose 'Creating NetMotion firewall rules for dual-NIC connection server or small deployment server...'
    New-NetFirewallRule -Name 'NmConn-UDP-5008-In' -DisplayName 'NetMotion Connections' -Description 'Allow inbound NetMotion Mobility connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5008 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-UDP-5009-In' -DisplayName 'NetMotion Service (UDP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol UDP -LocalPort 5009 -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-TCP-5009-In' -DisplayName 'NetMotion Service (TCP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Domain -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

}

# // Create fireawll rules for NetMotion analytics servers (NetMotion versions prior to 12.x)
If ($SmallDeploymentServer -or $AnalyticsServer) {

    Write-Verbose 'Creating NetMotion firewall rules for analytics/publisher server...'
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-TCP-5009-In' -DisplayName 'NetMotion Service (TCP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    If ($NmVersion -lt '12.50') {

        New-NetFirewallRule -Name 'NmDatabase-TCP-3306-In' -DisplayName 'NetMotion Analytics Database' -Description 'Allow inbound NetMotion Analytics database connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 3306 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -Name 'NmService-TCP-5673-In' -DisplayName 'NetMotion Analytics Service' -Description 'Allow inbound NetMotion Analytics service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5673 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    }

}

# // Create firewall rules for NetMotion publisher servers (NetMotion servers 12.x and later)
If ($SmallDeploymentServer -or $PublisherServer) {

    Write-Verbose 'Creating NetMotion firewall rules for analytics/publisher server...'
    New-NetFirewallRule -Name 'NmWebUI-TCP-80-In' -DisplayName 'NetMotion Web Management' -Description 'Allow inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 80 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name "NmWebUI-TCP-$WebUiPort-In" -DisplayName 'NetMotion Web Management Secure' -Description 'Allow secure inbound NetMotion web management connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort $WebUiPort -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -Name 'NmSvc-TCP-5009-In' -DisplayName 'NetMotion Service (TCP-In)' -Description 'Allow inbound NetMotion service connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5009 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    If ($NmVersion -ge '12.50') {

        $Rules = Get-NetFirewallRule | Where-Object DisplayName -like 'NetMotion Mobility Publisher*'

        ForEach ($Rule in $Rules) {

            $Rule.Group = 'NetMotion Mobility'
            $Rule | Set-NetFirewallRule

        }

    }

    Else {

        New-NetFirewallRule -Name 'NmPublisherAlert-TCP-5671-In' -DisplayName 'NetMotion Publisher Alert' -Description 'Allow inbound NetMotion publisher alert connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5671 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -Name 'NmPublisherData-TCP-5672-In' -DisplayName 'NetMotion Publisher Data' -Description 'Allow inbound NetMotion publisher data connections.' -Group 'NetMotion Mobility' -Protocol TCP -LocalPort 5672 -Direction Inbound -Profile Any -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null

    }

}

# // Clean up default NetMotion warehouse firewall rules
If ($SmallDeploymentServer -or $WarehouseServer) {

    Write-Verbose 'Adding existing NetMotion Warehouse firewall rules to the NetMotion Mobility firewall rule group...'

    If ($NmVersion -ge '12.50') {

        $Rules = Get-NetFirewallRule | Where-Object DisplayName -like 'NetMotion Mobility Warehouse*'

        ForEach ($Rule in $Rules) {

            $Rule.Group = 'NetMotion Mobility'
            $Rule | Set-NetFirewallRule

        }

    }

    Else {

        $Rule = Get-NetFirewallRule -DisplayName 'Mobility Warehouse'
        $Rule.Group = 'NetMotion Mobility'
        $Rule | Set-NetFirewallRule

        $Rule = Get-NetFirewallRule -DisplayName 'Mobility Warehouse SSL'
        $Rule.Group = 'NetMotion Mobility'
        $Rule | Set-NetFirewallRule

    }

}

# // Clean up default NetMotion bandwidth test server firewall rule
If ($BandwidthTestServer) {

    Write-Verbose 'Adding existing NetMotion Mobility Bandwidth Server firewall rule to the NetMotion Mobility firewall rule group...'
    $Rule = Get-NetFirewallRule -DisplayName 'Mobility Bandwidth Server'
    $Rule.Group = 'NetMotion Mobility'
    $Rule | Set-NetFirewallRule

}

# // Perform firewall hardening for dual-NIC gateway deployments
If ($EnhancedSecurity -and $DualNic) {

    If ($SmallDeploymentServer) {

        If ($NmVersion -ge '12.50') {

            $Rules = Get-NetFirewallRule | Where-Object DisplayName -like 'NetMotion Mobility Publisher*'

            Foreach ($Rule in $Rules) {

                $Rule.Profile = 'Domain'
                $Rule | Set-NetFirewallRule

            }

            $Rules = Get-NetFirewallRule | Where-Object DisplayName -like 'NetMotion Mobility Warehouse*'

            Foreach ($Rule in $Rules) {

                $Rule.Profile = 'Domain'
                $Rule | Set-NetFirewallRule

            }

        }

        Else {

            Write-Verbose 'Performing firewall hardening for NetMotion dual-NIC small deployment server...'
            Set-NetFirewallRule -DisplayName 'Mobility Warehouse' -Profile Public, Private -Enabled False
            Set-NetFirewallRule -DisplayName 'Mobility Warehouse' -Profile Domain -Enabled True
            Set-NetFirewallRule -DisplayName 'Mobility Warehouse SSL' -Profile Public, Private -Enabled False
            Set-NetFirewallRule -DisplayName 'Mobility Warehouse SSL' -Profile Domain -Enabled True

        }

    }

    Write-Verbose 'Performing firewall hardening for NetMotion dual-NIC connection server or small deployment server...'
    Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Profile Public, Private -Enabled False
    Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Profile Public, Private -Enabled False
    Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Profile Domain -Enabled True
    Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Profile Domain -Enabled True

}

# SIG # Begin signature block
# MIIhjgYJKoZIhvcNAQcCoIIhfzCCIXsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULfAzzN8bDu5e+G6QDOFc/hCj
# PJWgghs2MIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKR
# N6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZz
# lm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1Oco
# LevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH
# 92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRA
# p8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+g
# GkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU
# 8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/
# FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwj
# jVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQ
# EgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUae
# tdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LS
# cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftw
# ig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalW
# zxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQm
# h2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScb
# qyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLaf
# zYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbD
# Qc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0K
# XzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm
# 8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9
# gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8a
# pIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSY
# oAMCAQICEAitQLJg0pxMn17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIx
# MDQyOTAwMDAwMFoXDTM2MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0
# IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DF
# u8SFJjCfpI5o2Fz16zQkB+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1w
# JGSzjeIIfTR9TIBXEmtDmpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn
# +piASTWHPVEZ6JAheEUuoZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmje
# EL0UV13oGBNlxX+yT4UsSKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50
# pa85tqtgEuPo1rn3MeHcreQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+w
# OwnXx5syWsL/amBUi0nBk+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0Uo
# gzYqZihfsHPOiyYlBrKD1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXM
# u+NIUPN3kRr+21CiRshhWJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0td
# dGFNPxKRdt6/WMtyEClB8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBz
# hRAjIVlgimRUwcwhGug4GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkC
# zGw8DFYRAgMBAAGjggFZMIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBRoN+Drtjv4XxGG+/5hewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYI
# KwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1Ud
# IAQVMBMwBwYFZ4EMAQMwCAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9
# jQh27o+8OpnTVuACGqX4SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8
# Ol1IbZXVP0n0J7sWgUVQ/Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2
# vaFIGH7c2IAaERkYzWGZgVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI
# 1Rr+1yc//ZDRdobdHLBgXPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4
# M8hPOBSSmfXdzlRt2V0CFB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrO
# JukYvpAHsEN/lYgggnDwzMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcK
# BtYmZ7eS5k5f3nqsSc8upHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE
# 6BaRUotBwEiES5ZNq0RA443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0
# zh57ju+168u38HcT5ucoP6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpq
# QDBISzSoUSC7rRuFCOJZDW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD
# 7YZF9LRhbr9o4iZghurIr6n+lB3nYxs6hlZ4TjCCBsYwggSuoAMCAQICEAp6Soie
# yZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0
# IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBa
# Fw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7M
# XGzj4CUu0jHkPECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumj
# S0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD
# 0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De
# 1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D
# 7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/
# KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+
# X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DN
# kdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr
# 5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV
# 6J67m0uy4rZBPeevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIsp
# QnL3ebLdhOon7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYG
# Z4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGog
# j57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBP
# oE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMw
# gYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEF
# BQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d
# 5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC
# 6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8R
# yTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bem
# h2RPPkaJFmMga8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkw
# NuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+
# VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGuk
# zp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTm
# tQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qX
# sdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvT
# nMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwwggcCMIIE6qAD
# AgECAhABZnISBJVCuLLqeeLTB6xEMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEw
# HhcNMjExMjAyMDAwMDAwWhcNMjQxMjIwMjM1OTU5WjCBhjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1pc3Npb24gVmllam8xJDAi
# BgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGluZzEkMCIGA1UEAxMbUmlj
# aGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6svrVqBRBbazEkrmhtz7h05LEBIHp8fGlV19nY2gpBLnkDR8Mz/E
# 9i1cu0sdjieC4D4/WtI4/NeiR5idtBgtdek5eieRjPcn8g9Zpl89KIl8NNy1UlOW
# NV70jzzqZ2CYiP/P5YGZwPy8Lx5rIAOYTJM6EFDBvZNti7aRizE7lqVXBDNzyeHh
# fXYPBxaQV2It+sWqK0saTj0oNA2Iu9qSYaFQLFH45VpletKp7ded2FFJv2PKmYrz
# Ytax48xzUQq2rRC5BN2/n7771NDfJ0t8udRhUBqTEI5Z1qzMz4RUVfgmGPT+CaE5
# 5NyBnyY6/A2/7KSIsOYOcTgzQhO4jLmjTBZ2kZqLCOaqPbSmq/SutMEGHY1MU7xr
# WUEQinczjUzmbGGw7V87XI9sn8EcWX71PEvI2Gtr1TJfnT9betXDJnt21mukioLs
# UUpdlRmMbn23or/VHzE6Nv7Kzx+tA1sBdWdC3Mkzaw/Mm3X8Wc7ythtXGBcLmBag
# pMGCCUOk6OJZAgMBAAGjggIGMIICAjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAdBgNVHQ4EFgQUxF7do+eIG9wnEUVjckZ9MsbZ+4kwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+G
# TWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVT
# aWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQw
# OTZTSEEzODQyMDIxQ0ExLmNybDA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsG
# AQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEB
# BIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYI
# KwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwGA1Ud
# EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAEvHt/OKalRysHQdx4CXSOcgoayu
# FXWNwi/VFcFr2EK37Gq71G4AtdVcWNLu+whhYzfCVANBnbTa9vsk515rTM06exz0
# QuMwyg09mo+VxZ8rqOBHz33xZyCoTtw/+D/SQxiO8uQR0Oisfb1MUHPqDQ69FTNq
# IQF/RzC2zzUn5agHFULhby8wbjQfUt2FXCRlFULPzvp7/+JS4QAJnKXq5mYLvopW
# sdkbBn52Kq+ll8efrj1K4iMRhp3a0n2eRLetqKJjOqT335EapydB4AnphH2WMQBH
# Hroh5n/fv37dCCaYaqo9JlFnRIrHU7pHBBEpUGfyecFkcKFwsPiHXE1HqQJCPmMb
# vPdV9ZgtWmuaRD0EQW13JzDyoQdJxQZSXJhDDL+VSFS8SRNPtQFPisZa2IO58d1C
# vf5G8iK1RJHN/Qx413lj2JSS1o3wgNM3Q5ePFYXcQ0iPxjFYlRYPAaDx8t3olg/t
# VK8sSpYqFYF99IRqBNixhkyxAyVCk6uLBLgwE9egJg1AFoHEdAeabGgT2C0hOyz5
# 5PNoDZutZB67G+WN8kGtFYULBloRKHJJiFn42bvXfa0Jg1jZ41AAsMc5LUNlqLhI
# j/RFLinDH9l4Yb0ddD4wQVsIFDVlJgDPXA9E1Sn8VKrWE4I0sX4xXUFgjfuVfdcN
# k9Q+4sJJ1YHYGmwLMYIFwjCCBb4CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# Q29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhABZnISBJVCuLLq
# eeLTB6xEMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSfW33PUpPEyg+M+8Bjh+bb3M1OODANBgkq
# hkiG9w0BAQEFAASCAYBZq/f+AXgTsmxYqCpcGhw5VqGQ4Ghd0pytTqEZLHJ2B/tM
# Ls63OBlfy3QVW+XAHJ9y1zee0avBbF/oC2hnfYXrj/c5viKJQPDFCLDVygFSvFUs
# Mvvlbhr89cVyC1NH1XzHZvJbmkjf5sQwU485Q9mYl7wwUvJLBf4DHZrQ70UTeVRy
# he9QdlKDi9nTrKnXP2MbbyYJhDVEMSTcBb/fBfftCynR67fzJOhRrLR1tlxWyiMu
# EFHozkInikm8b5Z4bQgu6obMcLSFME5t7C3iphghAcYnitYFCb5/g1EfbL5undaE
# huDVkX2jYRc5anaDV9RJ6EXPYA89QVgn4tg5W3qtKlll34Z8PvnXrjqskFjvgzuT
# SH5rZjnQa1oRj371XTWBJtVX4C6w2GFlRwQAMLucj8IbhkTUSE9j9xcoCRv8fPYk
# aEZqE4/7sc5i8Ddgl76ylPNZWpYZAWnE3/r/KQOmU0biuUyoUBjIP6JHDhU+znkV
# eZ344lUm4B4xJb+8TQWhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5n
# IENBAhAKekqInsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjIwNTI3MjI0OTI2WjAv
# BgkqhkiG9w0BCQQxIgQgTzoPFD3wiNiFIlA+oH8k9snHxsaU0zffKqoMh7mwwFsw
# DQYJKoZIhvcNAQEBBQAEggIAOQr5s7Z2SKzU/JaBsLPzlyW1blH+HdMj7cRxmkja
# 4bqeZ9ADJ+H9wBwAVszOP4edV5vg6psPR5DQ9qYb1AwDiqgxl8JaVbxSVs6mM2X1
# BEh3n9YKX2emoE7KF/e3fOxBj22JawH95aExER4Bv5N75yXbkebBgmwjKCDmfAfv
# kyTijBKhuXzv57IPsnnTKW3cfvVgWLXGYrt6VfW/tifo69Hv7r1noE36yFuXm/GG
# EVK2ZHlsNO9oGQJNzDHKtfqPAzm9qYMeRWxQVYxgQhqnzaZX4lplkTQWNYiIypre
# yL0Pe75VQOVTVjLu7kEbLsEIWDKVII+C7DyQ1AiqN+cu9UDhT6jfY9lOoA5CL24H
# 9AelNFoB+NSV1Rb2+Q8WYyHnmGilq1vEA6HgdFMcIUQAdZrgd/qw+F1diLkssZY2
# DFdPBdX5rhLdSPN6ikM2v/Mm1nuq+Nw2vbHkYE3Fcmr/CmBsemVDoaBl23CVqmBm
# XlpQbvAaV7WWPdpQvCgeHwhThSodwVWoJALKc+XcumpxMDXnclYy2EK7JxCk4EyC
# Ds1uN7yu9VzdeDviCtcjoKvPsQ4J/+sTQuIvptnZF/GMvH2GBjTPnYkWj7CSZthR
# 0hLTuCxgt6PG+lMF33h+hb7ewy88FR+mS/mByJPhQVPKBkAoo3cMOL9IM+r5XKnc
# KIE=
# SIG # End signature block
