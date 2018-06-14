function Set-WEFSubscription {
    <#
        .Synopsis
        Set-WEFSubscription

        .DESCRIPTION
        Set properties on a Windows Eventlog Forwarding subscription 

        .NOTES
        Author: Andreas Bellstedt

        .LINK
        https://github.com/AndiBellstedt/WindowsEventForwarding

        .EXAMPLE
        Set-WEFSubscription
        Example text 

    #>
    [CmdletBinding( DefaultParameterSetName = 'ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'medium')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "InputObject", Mandatory=$true)]
        #[System.Management.Automation.PSCustomObject]
        $InputObject,

        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [String]
        $Name,

        [Parameter(ValueFromPipeline = $true, Position = 1, ParameterSetName = "ComputerName")]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,
		
        [Parameter(ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [PSCredential]
        $Credential,


        [String]
        $NewName,

        [string]
        $Description,
        
        [bool]
        $Enabled,

        [bool]
        $ReadExistingEvents,

        [ValidateSet("Events", "RenderedText")]
        [string]
        $ContentFormat,

        [string]
        $LogFile,

        [ValidateSet("en-US", "de-DE", "fr-FR", "es-ES", "nl-NL","it-IT")]
        [string]
        $Locale,

        [string]
        $Query,

        [timespan]
        $MaxLatency,

        [timespan]
        $HeartBeatInterval,
        
        [int]
        $MaxItems,

        [ValidateSet("HTTP", "HTTPS")]
        [string]
        $TransportName
    )

    Begin {
        $Local:TypeName = "$($BaseType).Subscription"

        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block 
        if ($Session) { $ComputerName = $Session }

        $nameBound = Test-PSFParameterBinding -ParameterName Name
        $computerBound = Test-PSFParameterBinding -ParameterName ComputerName
    }

    Process {
        Write-PSFMessage -Level Verbose -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        # Workarround parameter binding behaviour of powershell in combination with ComputerName Piping
        if (-not ($nameBound -or $computerBound) -and $ComputerName.InputObject -and $PSCmdlet.ParameterSetName -ne "Session") {
            if ($ComputerName.InputObject -is [string]) { $ComputerName = $env:ComputerName } else { $Name = "" }
        }
        
        # Checking Parameterset - when not inputobject query for existiing object to modiy 
        if($PsCmdlet.ParameterSetName -ne "InputObject") {
            Write-PSFMessage -Level Verbose -Message "Gathering $ComputerName for subscription $Name"
            $InputObject = Get-WEFSubscription -Name $Name -ComputerName $ComputerName -ErrorAction Stop
            if (-not $InputObject) {
                $message = "Subscription $Name not found"
                if($ComputerName) { $message = $message + " on " + $ComputerName }
                throw $message 
            }
        }

        foreach ($subscription in $InputObject) {
            #region Connecting and gathering prerequisites
            Write-PSFMessage -Level Verbose -Message "Processing $($subscription.Name) on $($subscription.ComputerName)" -Target $subscription.ComputerName
            
            switch ($PSBoundParameters.Keys) {
                "NewName" { "NewName" }
                "Description" {}
                "Enabled" { "Enabled" }
                "ReadExistingEvents" { $ReadExistingEvents }
                "ContentFormat" { $ContentFormat }
                "LogFile" {}
                "Locale" {}
                "Query" {}
                "MaxLatency" {}
                "HeartBeatInterval" {}
                "MaxItems" {}
                "TransportName" {}

                Default {}
            }
        }
    }

    End {
        # Clearing up the mess of variables
        Remove-Variable -Name TypeName -Force -Confirm:$false -WhatIf:$false -Debug:$false -Verbose:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
}