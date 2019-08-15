# New Dynamics User Creation Automation
Author: Kyle Martin

Required Modules:
AzureAD Powershell Module
MSOnline Powershell Module
Microsoft.XRMDATA Powershell module for Dynamics
Microsoft.XRM.Tooling CRM Connector module for Dynamics

Usage:

This script requires data fed from a CSV. The headers are:
Username,Email,License,xPerido,GPBO,BU,Team,SR

Username: AD Domain login name
Email: Email address
License: License type, CS for Customer Service, TM for Team Members.
xPerido: Yes/No, if the user requires xPerido and related config.
GPBO: This is a custom field that can be modified.
BU: Business unit to assign
Team: Additional team to be assigned
SR: Additional security role to be assigned

Example CSV:
Username,Email,License,xPerido,GPBO,BU,Team,SR
TestADUsername,Test.Email@Contoso.com.au,CS,,,,,

If any fields are not required - leave them blank.

Define CSV Path in variable at line 10. 

Before running the script, please add variables for Azure DataSync server if required, your Dynamics instance URL & a path for your logfile. You will also need to add your O365 tenant name for licensing sku's. 

If you require adding users to AD/AAD security groups as part of the on board process, use these variables, otherwise comment them out.

I also recommend using a method to store your encrypted credentials rather than using Get-Credential to run your AD Sync session. The person running the script will require access to edit AD/AzureAD groups, assign licenses in O365 & the required permissions in the dynamics instance. 

Purpose:

This script will set up an internal Dynamics Online user. 
 - Add user to required security groups in AD/AAD.
 - Assign licenses for Dynamics & PowerBI.
 - Sync AD to AAD
 - Add Dynamics Business Units, Set custom attribute on users record & assign teams if required.
 - Add security roles to Dynamics user.
 - Configure Dynamics mailbox by scheduling mailbox test & approving. 

Additional business units can be defined at lines 222 to 232. Uncomment if required in the script. 

