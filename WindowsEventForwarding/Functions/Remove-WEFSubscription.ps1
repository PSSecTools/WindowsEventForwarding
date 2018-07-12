function Remove-WEFSubscription {
    <#
        .Synopsis
            Remove-WEFSubscription

        .DESCRIPTION
            Remove a Windows Eventlog Forwarding subscription 

        .PARAMETER InputObject
            Pipeline catching object for Get-WEFSubscription

        .PARAMETER ComputerName
            The computer(s) to connect to.
            Supports PSSession objects, will reuse sessions.

            Available aliases: "host", "hostname", "Computer", "DNSHostName"

        .PARAMETER Session
            PSSession(s) to connect to.

        .PARAMETER Name
            Name of the subscription to remove.
            Only needed when InputObject is not used.
            Must be specified when piping in a computername or a session.

            Available aliases: "DisplayName", "SubscriptionID", "Idendity"

        .PARAMETER Credential
            The credentials to use on remote calls.

        .PARAMETER Force
            Suppress the user confirmation.

        .EXAMPLE
            PS C:\> Remove-WEFSubscription -Name "Subscription1"
            
            Remove the subscription "Subscription1" to "Subscription1New"

        .EXAMPLE
            PS C:\> Get-WEFSubscription -Name "Subscription1" | Remove-WEFSubscription
            
            Remove "Subscription1" by using the pipeline.

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding( DefaultParameterSetName = 'ComputerName',
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0, ParameterSetName = "InputObject")]
        [WEF.Subscription[]]
        $InputObject,

        [Parameter(ValueFromPipeline = $false, Position = 0, Mandatory = $false, ParameterSetName = "ComputerName")]
        [Parameter(ValueFromPipeline = $false, Position = 0, Mandatory = $false, ParameterSetName = "Session")]
        [Alias("DisplayName", "SubscriptionID", "Idendity")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [Parameter(ValueFromPipeline = $true, Position = 1, Mandatory = $false, ParameterSetName = "ComputerName")]
        [Alias("host", "hostname", "Computer", "DNSHostName")]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = "Session")]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [PSCredential]
        $Credential,

        [Switch]
        $Force
    )
    
    Begin {
        # If session parameter is used -> transfer it to ComputerName,
        # The class "PSFComputer" from PSFramework can handle it. This simplifies the handling in the further process block 
        if ($Session) { $ComputerName = $Session }
        if ($Force) { $ConfirmPreference = "None" }
    }

    Process {
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        #region query specified subscription when not piped in
        if($PsCmdlet.ParameterSetName -ne "InputObject") {
            # when not inputobject --> query for existing object to modify 
            Write-PSFMessage -Level Verbose -Message "Gathering $ComputerName for subscription $Name"
            try {
                $InputObject = Get-WEFSubscription -Name $Name -ComputerName $ComputerName -ErrorAction Stop
            } catch {
                Stop-PSFFunction -Message "Error finding subscription '$name' on computer $computer" -ErrorRecord $_ -EnableException $true
            }
            if (-not $InputObject) {
                $message = "Subscription $Name not found"
                if($ComputerName) { $message = $message + " on " + $ComputerName }
                Stop-PSFFunction -Message $message  -ErrorRecord $_ -EnableException $true
            }
        }
        #endregion query specified subscription when not piped in

        foreach ($subscription in $InputObject) {
            Write-PSFMessage -Level Verbose -Message "Processing '$($subscription.Name)' on '$($subscription.ComputerName)'" -Target $subscription.ComputerName
            #region preparation
            #endregion preparation

            #region Reomve subscription from system
            # Delete existing subscription. execute wecutil to delete subscription with redirectoing error output
            if ($pscmdlet.ShouldProcess("Subscription: $($subscription.Name) on computer '$($subscription.ComputerName)'", "Remove")) {
                Write-PSFMessage -Level Verbose -Message "Remove subscription '$($subscription.Name)' on computer '$($subscription.ComputerName)'" -Target $subscription.ComputerName
                
                $invokeParams = @{
                    ComputerName  = $subscription.ComputerName
                    ErrorAction   = "Stop"
                    ErrorVariable = "ErrorReturn"
                    ArgumentList  = @(
                        $subscription.Name
                    )
                }
                if($Credential) { $invokeParams.Add("Credential", $Credential)}

                try {
                    $null = Invoke-PSFCommand @invokeParams -ScriptBlock { 
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        . "$env:windir\system32\wecutil.exe" "delete-subscription" "$($args[0])" 2>&1 
                    }
                    if($ErrorReturn) { Write-Error "" -ErrorAction Stop}
                } catch {
                    Write-PSFMessage -Level Verbose -Message "Error on remove subscription. This should not happen - unexpected behaviour." -Target $subscription.ComputerName
                    $ErrorReturn = $ErrorReturn | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'wecutil.exe' }
                    $ErrorMsg = [string]::Join(" ", $ErrorReturn.Exception.Message.Replace("`r`n"," "))
                    throw "Error removing subscription '$($subscription.Name)' on computer '$($subscription.ComputerName)'! $($ErrorMsg)"
                }
            }
            #endregion Reomve subscription from system
        }
    }

    End {
    }
}