# Changelog 
## Version 1.0.0.5 : 2018-08-04 
- Fix: outputting multiple object on WEFsubscriptionRuntimeStatus for active subscriptions. Error was - only the last computer object was outputted.

## Version 1.0.0.4 : 2018-07-30 
- Fix: some documentation
- Fix: code review to meet PSScriptAnalyzer rules
- Fix: uncritical error in Set-WEFSubscription (remove-variable didn't work)

## Version 1.0.0.0 : 2018-07-27 initial version
- 11 functions implemented
   - Disable-WEFSubscription
   - Enable-WEFSubscription
   - Get-WEFSubscription
   - Get-WEFSubscriptionRuntimestatus
   - New-WEFCollectorInitiatedSubscription
   - New-WEFSourceInitiatedSubscription
   - New-WEFSubscription
   - Remove-WEFSubscription
   - Rename-WEFSubscription
   - Resume-WEFSubscription
   - Set-WEFSubscription
- Types for convenience and readable tables, lists and wide views
