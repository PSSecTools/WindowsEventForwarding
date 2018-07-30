function Global:Format-WEFSubscriptionRuntimeSatusErrorMessage {
    <#
        .Synopsis
            Regex helper function for runtimestatus error messages from WEF subscription

        .DESCRIPTION
            Helper function for parsing the messagetext out of a WEF Status error message object (xml styled)

        .PARAMETER Message
            The xml errormesage from the RuntimeStatus

        .PARAMETER NoQuotReplace
            Message often contain &quot representing '.
            If this switch is specified, no replacement of &quot will be done for the message.

        .EXAMPLE
            PS C:\> Format-WEFSubscriptionRuntimeSatusErrorMessage -Message $Message

            Parse out the Message block from a WEFsubscriptionRuntimeStatus XML message object

        .NOTES
            Author: Andreas Bellstedt

        .LINK
            https://github.com/AndiBellstedt/WindowsEventForwarding
    #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param (
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [String[]]
        $Message,

        [switch]
        $NoQuotReplace
    )

    begin {
    }

    process {
        Write-PSFMessage -Level Debug -Message "ParameterNameSet: $($PsCmdlet.ParameterSetName)"

        $match = Select-String -InputObject $Message -Pattern '\<f:Message\>(?<RuntimeStatus>.*) \<\/f:Message\>'
        $result = $match.Matches.groups.Where( {$_.Name -like 'RuntimeStatus'}).Value
        if ($result) {
            if ($NoQuotReplace) {
                Write-PSFMessage -Level Debug -Message "Message match found. No quot replacement specified. Outputting matched message."
                $result
            }
            else {
                Write-PSFMessage -Level Debug -Message "Message match found. Replacement of &quot done before outputting message."
                $result.Replace('&quot;', "'")
            }
        }
        else {
            Write-PSFMessage -Level Debug -Message "No match for Message found. Outputting native message."
            $Message
        }
    }

    end {
    }
}

(Get-Command -Name Format-WEFSubscriptionRuntimeSatusErrorMessage).Visibility = 'Private'