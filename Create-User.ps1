#Create internal Dynamics 365 User. 
#Author: Kyle Martin
#Date: 13/6/2019
#Modified: 15/8/2019
#Purpose:
#End to end configures a staff members Dynamics 365 account for use with ePortfolio365.


#Variables
$CSVPath = "Path\Users.csv"
$DynamicsURL = ""
$AADSyncServer = ''
$O365Tenant = ""
$ADGroups = @('ADGroup1', 'ADGroup2')
$AADGroups = @('GroupObjectID1', 'GroupObjectID2')
$credentials = Get-Credential
[string]$date = Get-Date -format "yyyyMMdd"
$LogFile = "Path\Log_$Date.Log"

#Required modules
Import-Module .\Modules\XRM\Microsoft.Xrm.Tooling.CrmConnector.PowerShell.psd1
Import-Module .\Modules\XRMDATA\Microsoft.Xrm.Data.PowerShell.psd1
Import-Module .\Modules\Azure\AzureAD.psd1
Import-Module .\Modules\MSOnline\MSOnline.psd1
Import-Module "$env:windir/System32/WindowsPowerShell/v1.0/Modules/ActiveDirectory/ActiveDirectory.psd1"


#Logging
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [AllowEmptyString()]
        [string]$message
    )

    $timeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $line = "$timeStamp - $message"
    
    Write-Output $Line | Tee-Object -FilePath $logfile -Append
}



#License Dynamics & PowerBI (This can be cleaned up).
function Add-DynamicsLicenses { 


    
    #Customer Service License
    If($User.License -EQ 'CS'){

    Add-ADGroupMember -Identity "Activate Microsoft Dynamics for Customer Service" -Members $Global:UserNameG

    # Get License Counts
    $csLicense = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -eq "${O365Tenant}:DYN365_ENTERPRISE_CUSTOMER_SERVICE"}
    $csAvailable = ($csLicense.ActiveUnits + $csLicense.WarningUnits) - $csLicense.ConsumedUnits

    # Check if we have licenses to assign
    if($csAvailable -gt 0) {       

        # Assign the correct licenses 
        Get-MsolUser -UserPrincipalName $Global:EmailLU | Set-MsolUserLicense -AddLicenses "${O365Tenant}:DYN365_ENTERPRISE_CUSTOMER_SERVICE" | Out-Null

    } else {
        Throw "No Dynamics CS Licenses available"
    }

    #Team Member License
   If($User.License -Eq 'TM'){

   Add-ADGroupMember -Identity "Activate Microsoft Dynamics for Team Members" -Members $Global:UserNameG
    
    $tmLicense = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -eq "${O365Tenant}:DYN365_TEAM_MEMBERS"}
    $tmAvailable = ($tmLicense.ActiveUnits + $tmLicense.WarningUnits) - $tmLicense.ConsumedUnits

        # Check if we have licenses to assign
    if($tmAvailable -gt 0) {       

        # Assign the correct licenses
        Get-MsolUser -UserPrincipalName $Global:EmailLU | Set-MsolUserLicense -AddLicenses "${O365Tenant}:DYN365_TEAM_MEMBERS" | Out-Null

    } else {
        Throw "No Dynamics TM Licenses available"
    }

}

}
    #PowerBI Licenses
    Add-ADGroupMember -Identity "Activate Microsoft Power BI Pro" -Members $Global:UserNameG
    $pbiLicense = Get-MsolAccountSku | Where-Object {$_.AccountSkuId -eq "${O365Tenant}:POWER_BI_PRO"}
    $pbiAvailable = ($pbiLicense.ActiveUnits + $pbiLicense.WarningUnits) - $pbiLicense.ConsumedUnits

        #Check if we have licenses to assign
    if($pbiAvailable -gt 0) { 
                  Get-MsolUser -UserPrincipalName $Global:EmailLU | Set-MsolUserLicense -AddLicenses "${O365Tenant}:POWER_BI_PRO" | Out-Null

    } else {
        Throw "No PowerBI Pro licenses available"
    }

}

#Adds users to AD group required for Dynamics (AD & AAD)
Function Add-DynamicsADGroups{
    #Grab the AAD Users ID for use later
    $AADMemberID = Get-AzureADUser -ObjectId $Global:EmailLU | Select-Object ObjectId


    #Make sure users aren't already in the groups by testing the first item of the group array
    $MemberValidateAAD = Get-AzureADGroupMember -ObjectId $AADGroups[0] | Where-Object UserPrincipalName -Like $Global:EmailLU
    $MemberValidateAD = Get-ADGroupMember -Identity $ADGroups[0] | Where-Object SamAccountName -Like $Global:UserNameG

    
    Try{  
 
    If(!($MemberValidateAD))
    {
        foreach($ADGroup in $ADGroups)
        {        
        Add-ADGroupMember -Identity $ADGroup -Members $Global:UserNameG
        }
    }
    Else
    {
        Write-Log -message "User is already in AD Groups."
    }

    If(!($MemberValidateAAD))
    {
        foreach($AADGroup in $AADGroups)
        {        
            Add-AzureADGroupMember -ObjectId $AADGroup -RefObjectId $AADMemberID.ObjectId

        }
    }
    Else
    {
        Write-Log -message "User is already in AAD Groups."
    }

    #This is for application deployment (xPerido plugin for word.) Uncomment if you require this.
    <#
    If($User.xPerido -eq "Yes"){
    Add-ADGroupMember -Identity "XperiDo Word Add-in Application" -Members $Global:UserNameG
    }#>

    }Catch{

    Throw "Error adding AD Groups"

    }

        }

    
#Get credentials for use with script & connect to required services. 
Function Import-Services{
    $LoggedUser = $Env:USERNAME
    $LoggedUserEmail = Get-ADUser -Identity $LoggedUser | Select-Object UserPrincipalName
    $LoggedEmail = $LoggedUserEmail.UserPrincipalName
    $Admin = Get-Credential("$LoggedEmail")
    Connect-MsolService -Credential $Admin
    Connect-AzureAD -Credential $Admin | Out-Null
    Connect-CrmOnline -ServerUrl $DynamicsURL -Credential $Admin | Out-Null 
}


#Sync AAD & Wait for user to appear in Dynamics before continuing
function Invoke-AADSync {
    

    $session = New-PSSession -ComputerName $AADSyncServer -Credential $credentials

    Invoke-Command -Session $session -ScriptBlock {Import-Module -Name 'ADSync'} | Out-Null
    Invoke-Command -Session $session -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta} | Out-Null
    Remove-PSSession $session

    $TestDYNUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute internalemailaddress -FilterOperator eq -FilterValue $Global:EmailLU -Fields domainname     
    
    Write-Log "Waiting for user to appear in Dynamics... this can take up to an hour!"

    Do{

    Write-Log "Still waiting for user to appear in Dynamics..."
    Start-Sleep -s 5
    $TestDYNUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute internalemailaddress -FilterOperator eq -FilterValue $Global:EmailLU -Fields domainname     

    }While($TestDYNUser.Count -lt 1)

    Write-Log "The user has appeared in Dynamics! Continuing with user creation."

}

#Adds business unit and teams if required to user. Also assigns employee code.
Function Add-DynamicsBU
{

    
    #Get user info.
    $crmUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute internalemailaddress -FilterOperator eq -FilterValue $Global:EmailLU -Fields domainname
    $systemUserId = $crmUser.CrmRecords[0].systemuserid.Guid
   

    #Get business unit
    $businessUnit = Get-CrmRecords -EntityLogicalName businessunit -FilterAttribute name -FilterOperator eq -FilterValue $Global:businessUnitName -Fields businessunitid
    
    #Set primary business unit
    if($businessUnit.CrmRecords.Count -eq 0)
    {
        Throw "Business Unit $Global:businessUnitName does not exist"
        return
    }
    else
    {
        Write-Log "Moved $Global:EmailLU to $Global:businessUnitName"
        $businessUnitId = $businessUnit.CrmRecords[0].businessunitid.Guid
        Set-CrmUserBusinessUnit -BusinessUnitId $businessUnitId -UserId $systemUserId -ReassignUserId $systemUserId
    }    

    #Second business team. Uncomment if required & set IDs. 
   # If($User.Team -eq "General"){
    
   #  Add-CrmRecordAssociation -conn $conn -EntityLogicalName1 team -Id1 <#ID#>"" -EntityLogicalName2 systemuser -id2 $systemUserId -RelationshipName teammembership_association

#}

   # If($User.Team -eq "Paralegal"){
    
    # Add-CrmRecordAssociation -conn $conn -EntityLogicalName1 team -Id1 <#ID#>"" -EntityLogicalName2 systemuser -id2 $systemUserId -RelationshipName teammembership_association

#}

        #Set Employee Code on record
        Set-CrmRecord -EntityLogicalName systemuser -Id $systemUserId -Fields @{"ep_employeecode"="$Global:UserNameG"}
}


#Adds security roles to user (This can be cleaned up)
Function Add-DynamicsSR
{

    #Get business unit
    $businessUnit = Get-CrmRecords -EntityLogicalName businessunit -FilterAttribute name -FilterOperator eq -FilterValue $Global:businessUnitName -Fields businessunitid
    $businessUnitId = $businessUnit.CrmRecords[0].businessunitid.Guid
    $crmUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute internalemailaddress -FilterOperator eq -FilterValue $Global:EmailLU -Fields domainname
    $systemUserId = $crmUser.CrmRecords[0].systemuserid.Guid


   


    $Counter = $Global:SRname | Measure-Object -Line -Character -Word
    
    #Add additional Security Role if present in CSV (Hacky - can be cleaned up)
 If($Global:SRname -and $User.xPerido -eq "Yes"){
    $SRS = @("$Global:SRname", "mscrm-addons general security role", "XperiDo Designer")  
    }Else{
    $SRS = @("$Global:SRname", "mscrm-addons General Security Role", "XperiDo User")
    }
    If($Counter.Words -lt 2){
    $SRS = $SRS | Select-Object -Skip 1
    }


#Loop through security role array and add them.

    ForEach($SR in $SRS){

    $fetch = @"
<fetch version="1.0" output-format="xml-platform" mapping="logical" distinct="true" no-lock="true">
  <entity name="role">
    <attribute name="roleid" />
    <filter type="and">
      <condition attribute="name" operator="eq" value="{0}" />
      <condition attribute="businessunitid" operator="eq" value="{1}" />
    </filter>
  </entity>
</fetch>
"@

    $fetch = $fetch -F $SR, $businessUnitId

    $securityRole = Get-CrmRecordsByFetch -Fetch $fetch

    if($securityRole.CrmRecords.Count -eq 0)
    {
        Throw "SecurityRole $SR does not exist"
        return
    }
    else
    {
        Write-Log "Assigned $SR to $Global:EmailLU"
        $securityRoleId = $securityRole.CrmRecords[0].roleid.Guid
        Add-CrmSecurityRoleToUser -UserId $systemUserId -SecurityRoleId $securityRoleId
    }    
    }
}


#Add user settings required (Remove/Add Settings, below are example settings).
function Set-DynamicsUserSettings{


  $crmUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute internalemailaddress -FilterOperator eq -FilterValue $Global:EmailLU -Fields domainname
  $systemUserId = $crmUser.CrmRecords[0].systemuserid.Guid


    $userSettings = Get-CrmRecord -conn $conn -EntityLogicalName usersettings -Id $systemUserId -Fields 'paginglimit', 'timezonecode', 'transactioncurrencyid', 'issendasallowed', 'reportscripterrors', 'localeid'       
    $usersettings | ForEach-Object {$_.paginglimit = '250'; Set-CrmUserSettings -conn $conn -CrmRecord $_} #Records per page 250
    $usersettings | ForEach-Object {$_.timezonecode = '255'; Set-CrmUserSettings -conn $conn -CrmRecord $_} #Timezone to GMT 10 Mel/Syd/Can
    $usersettings | ForEach-Object {$_.issendasallowed = $true; Set-CrmUserSettings -conn $conn -CrmRecord $_} #Send on behalf allowed
    $usersettings | ForEach-Object {$_.reportscripterrors = '3'; Set-CrmUserSettings -conn $conn -CrmRecord $_} #Report script errors (No)
    $usersettings | ForEach-Object {$_.localeid = '3,081'; Set-CrmUserSettings -conn $conn -CrmRecord $_} #Locale ID EN AU

}

#Configure mailbox (Approve & Test)
function Set-D365MailSettings{

  $crmUser = Get-CrmRecords -EntityLogicalName systemuser -FilterAttribute internalemailaddress -FilterOperator eq -FilterValue $Global:EmailLU -Fields domainname
  $systemUserId = $crmUser.CrmRecords[0].systemuserid.Guid


   $Mailbox = Get-CrmUserMailbox -UserId $systemUserId 
   $MBoxID = $Mailbox.MailboxID.Guid

   Try{
   #Approve the mailbox
   Approve-CrmEmailAddress -UserId $systemUserId
   #Schedule the test
   Set-CrmRecord -EntityLogicalName mailbox -Id $MBoxID -Fields @{"testemailconfigurationscheduled"=$true}

   }Catch{

   Throw "Error: Mailbox not found or configured. Cleanup manually if required."


   }
   

  }


#Import the CSV
$Users = Import-CSV -Path $CSVPath

#Login to the services
Write-Log -message "Prompting user for O365 Credentials to login to required services."
Write-Log -message ""

Import-Services

##################
#Start Script    #
##################
Foreach($User in $Users){
#Set variables for functions
$Global:UserNameG = $User.Username
$Global:EmailLU = $User.Email
$Global:businessUnitName = $User.BU
$Global:SRName = $User.SR


Write-Log -message "Creating Dynamics365 EP User - $Global:UserNameG"
Write-Log -message ""

Write-Log -message "Adding $Global:UserNameG to security groups"
#AD Groups
Add-DynamicsADGroups
Write-Log -message "Added $Global:UserNameG to security groups"
Write-Log -message ""

#Licensing
Write-Log -message "Assigning licenses for $Global:UserNameG."
Add-DynamicsLicenses
Write-Log -message "Assigned licenses for $Global:UserNameG."
Write-Log -message ""


#Waiting for user to appear in EP365.
Write-Log -message "Sleeping to give time for the user to appear"
Start-Sleep -s 120
Write-Log -message "Continuing with the user creation process."
Write-Log -message ""


#Invoke AD Sync
Write-Log -message "Forcing sync from AD to AAD... please wait a minute"
Invoke-AADSync
Write-Log -message "Just going to wait a few more seconds to be sure..."
Start-Sleep -s 10
Write-Log -message "AAD should now be up to date with our changes"
Write-Log -message ""

#Assign Business Unit & Set employee code.
Write-Log -message "Adding business units, setting employee code and assigning team for $Global:UserNameG"
Add-DynamicsBU
Write-Log -message "Business units for $Global:UserNameG added."
Write-Log -message "Employee code $Global:UserNameG added."
Write-Log -message ""

#Assign security roles
Write-Log -message "Adding security roles for $Global:UserNameG"
Add-DynamicsSR
Write-Log -message "Security roles for $Global:UserNameG added."
Write-Log -message ""


#Update user settings
Write-Log -message "Configuring user settings for $Global:UserNameG"
Set-DynamicsUserSettings
Write-Log -message "User settings configured for $Global:UserNameG."
Write-Log -message ""

#Configure Dynamics mailbox settings
Write-Log -message "Configuring Mailbox settings for $Global:UserNameG."
Set-D365MailSettings
Write-Log -message "Mailbox settings configured for $Global:UserNameG."
Write-Log -message ""


#Finish
Write-Log -message "Dynamics (eP365) user account configured for $Global:UserNameG."
Write-Log -message ""
}

Write-Log -message "User(s) have been created."


