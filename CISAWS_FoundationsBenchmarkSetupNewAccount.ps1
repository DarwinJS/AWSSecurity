<#
.SYNOPSIS
Configures a fresh AWS trial account to be comliant with the CIS AWS Foundations Benchmark v1.0

.DESCRIPTION

This script will configure a fresh AWS trial account to be compliant with the CIS AWS Foundations Benchmark.
In addition to making the entire account compliant it can create a sample Admin group, ReadOnly group and
sample users for each.  It can also create a sample, compliant Public and Private Subnets.

This script is intended as a learning tool and a jump start point from which to build your own
automation.  As a learning tool it does not contain error trapping nor idempotence as these
elements - while very necessary for a production environment - tend to obscure the main working code
among a lot of cautionary logic and pre-checking logic.

This script uses AWS CLI commands instead of AWS PowerShell CMDLets so that it can run on both 
Windows and Linux.  This script was tested for PowerShell Core on Linux using CentOS 7.
How to Install PowerShell on Linux:
https://blogs.msdn.microsoft.com/powershell/2016/08/18/powershell-on-linux-and-open-source-2/

This script's references to CIS AWS Foundations recommendations numbers is based on version 1.1.0
of the benchmark.

It satisfies the initial setup for the following items for version 1.1.0 of the Foundations Benchmark:
1.5-1.12, 2.1-2.8, 4.1-4.4

The following items are not handled either because they cannot be done via automation or because
they involve ongoing audit of resources or settings that are not defined in a new account:
1.1-1.4, 1.13-1.15

The following items require on going management as resources are added to the account:
1.1-1.4, 1.15, 2.8, 4.1, 4.2, 4.4


You only need to take the following two steps to use this script on a pristine AWS account:
1) Setup a New AWS Account
2) Setup Access Keys for the Root Account (Which are deleted as soon as possible by the script)

Setting up access keys for the root account is a little different than for IAM accounts:
1) Logon as root
2) In the upper right corner click your root account name (displays as First name Last name)
3) From the drop down, select "Security Credentials"
4) On the "Your Security Credentials" page click "Access Keys (Access Key ID and Secret Access Key)
5) Click "Create New Access Key"
6) Copy or download the keys

.COMPONENT
DarwinJSTemplate
.ROLE
DarwinJSTMPL_1CoreLibrary.ps1
.PARAMETER Force
Suppresses all prompting - use with great caution.
.NOTES

Linux Adaptations:
*) Create a $env:temp when linux is detected
*) $env:VARIABLENAMES are now cases sensitive
*) Use Join-Path to avoid problems with / versus \ in file paths

  SCRIPT REVISION NOTES:
   INIT  DATE        VERSION   NOTES
   DJS   2016-04-23  1.10      Initial Release
   DJS   2016-04-23  2.10      Linux Adaptations

  UNIT TEST AND VERIFICATION INSTRUCTIONS:
   - Sample Unit test instructions.
   #>

Param ([switch]$Force)

If ((!(Test-Path env:temp)) -AND (Test-Path '/tmp'))
{
  Write-Host "We are running on Linux, setting up TEMP environment variable"
  $env:temp = '/tmp'
}

#region Global Variables
$ErrorActionPreference = 'Stop'
$DarwinJSTMPL_MainScriptVersion = '1.1.310'
$DarwinJSTMPL_TopLevelInvocation = $MyInvocation
$AWSBenchMarkName = "CIS AWS Foundations Benchmark"
$AWSBenchMarkVersion = "1.0.0"
$ScriptFullPath = $MyInvocation.MyCommand.Definition
$ScriptFileName = Split-Path -Leaf $ScriptFullPath

#Create Root Access Keys and place them here.  They are deleted from the root user as soon as possible by this script.
#If you do not wish to create root access keys, then perform the section "#satisfies 1.1,1.15" via the console
$env:AWS_ACCESS_KEY_ID=''
$env:AWS_SECRET_ACCESS_KEY=''
$env:AWS_DEFAULT_REGION='us-east-1'
$env:AWS_ACCOUNT=aws ec2 describe-security-groups --group-names 'Default' --query 'SecurityGroups[0].OwnerId' --output text

If (($env:AWS_ACCESS_KEY_ID -eq $null) -OR ($env:AWS_SECRET_ACCESS_KEY -eq $null))
{Throw "Access Keys are incomplete, please add them and retry"}

#endregion Global Variables

#region IAM Variables [Benchmark Section 1]
  $NewUserPassword = '' #If password is left blank, a password will not be created for sample accounts
  $AdministratorsGroupName = 'AdminUsers'
  $AccountSetupUser = 'SecurityAutomation'
#endregion IAM Variables [Benchmark Section 1]

#region Sample Assets Variables
  #IAM Sample Assets
  $ReadOnlyUsersGroupName = 'ReadOnlyUsers'
  $SampleAdminUser = 'SampleAdminUser'
  $SampleReadOnlyUser = 'SampleReadOnlyUser'

  #Networking Sample Assets
  $NewCISVPC_CIDR='10.50.0.0/16'
  $NewCISVPC_Name='CIS AWS Foundations VPC'

  $NewCISSubnetPublic_CIDR='10.50.1.0/24'
  $NewCISSubnetPublic_NAME='CIS AWS Foundations PUBLIC'
  #AZ will be the first AZ in the default Region
  $NewCISSubnetPublic_AZ="$env:AWS_DEFAULT_REGION" + "b"

  $NewCISSubnetPrivate_CIDR='10.50.2.0/24'
  $NewCISSubnetPrivate_NAME='CIS AWS Foundations PRIVATE'
  #AZ will be the first AZ in the default Region
  $NewCISSubnetPrivate_AZ="$env:AWS_DEFAULT_REGION" + "b"
#endregion Sample Assets Variables

#region Network Variables [Benchmark Section 4]
  $MakeAllExistingVPCsInAccountCompliant = $False
#endregion Network Variables [Benchmark Section 4]

#region Logging Variables [Benchmark Section 2]
  $CloudTrailBucketName="$($env:AWS_ACCOUNT)cloudtrailforallregions" #Underbar and upper case not allowed dispite: http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-log-group-log-stream-naming-for-cloudtrail.html
  $CloudTrailName = $CloudTrailBucketName
  $CloudTrailRole = 'CloudTrailServiceRole'
  $CloudTrailLogRetentionDays = 365 #Possible values: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653.

  $AWSConfigBucketName="$($env:AWS_ACCOUNT)awsconfigforallregions" #Underbar and upper case not allowed
  $AWSConfigRole = 'AWSConfigServiceRole'
  $AWSConfigSNSTopic = 'AWSConfig'

  $FlowLogsRole= 'FlowLogsRole'
  $FlowLogsGroup  = "$($env:AWS_ACCOUNT)flowlogsforallregions"
  $FlowLogsLogRetentionDays = 365 #Possible values: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653.
  $FlowLogsFilter = 'REJECT' #When doing least privilege security group engineering on a pre-existing environment, temporarily using 'ALL' for this parameter can be very helpful.

#endregion Logging Variables [Benchmark Section 2]

#region Monitoring Variables [Benchmark Section 3]
  $MetricNameSpaceforBenchmark = 'CIS Security'
  $SNSTopicForSecurityAlerts = 'CISAWSAlert'
  $EmailforSecurityAlerts = 'AWSAlerts@safetymail.info'

#endregion Monitoring Variables [Benchmark Section 3]

#region supporting functions
Function Console-Prompt {
  Param( [String[]]$choiceList,[String]$Caption = "Please make a selection",[String]$Message = "Choices are presented below",[int]$default = 0 )
  $choicedesc = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
  $choiceList | foreach {
  $comps = $_ -split '='
  $choicedesc.Add((New-Object "System.Management.Automation.Host.ChoiceDescription" -ArgumentList $comps[0],$comps[1]))}
  $Host.ui.PromptForChoice($caption, $message, $choicedesc, $default)
}

Function PauseScript ([string]$PauseMessage="`r`nPress any key to continue...") {

  If ($psISE) 
  {
    # The "ReadKey" functionality is not supported in Windows PowerShell ISE.
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("$PauseMessage", 0, "Click OK to continue.", 0)
    Return
  }

  Write-Host $PauseMessage ; $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
}

#endregion supporting functions

$ExecutionHeading = @"

********************************************************************************************************
  $ScriptFileName (Version: $DarwinJSTMPL_MainScriptVersion)
  On PowerShell Version: $($psversiontable.psversion)
  Configuring: $AWSBenchMarkName (Version: $AWSBenchmarkVersion)
  For AWS Account: $env:AWS_ACCOUNT
********************************************************************************************************

"@

Write-Output $ExecutionHeading

#region Are you sure (with dire warning)
If (!$Force)
{
  switch (Console-Prompt -Caption "****************************`r`n  !!! CRITICAL WARNING !!!`r`n  AWS ACCOUNT $env:AWS_ACCOUNT`r`n****************************" -Message "This script has the potential to bring a production environment to a screeching halt.  `r`nIt is only intended to be used on a pristine AWS account where no existing resources are deployed or configured.  `r`n`r`nARE YOU SURE YOU WISH TO CONTINUE USING AWS ACCOUNT: $env:AWS_ACCOUNT ?`r`n`r`n" -choice "&YES I Wish To Make MASSIVE Security Changes to This AWS Account=YES I Wish To Make MASSIVE Security Changes to This AWS Account", "&Cancel NOW!=Cancel NOW!" -default -1)
  {
  1 {
    Write-Warning "Script was exited by user."
    Exit
    }
  }
}
Else
{
  Write-Output "`r`n`r`n*********************`r`n  CRITICAL WARNING: -Force was used, overriding the consent prompt and making high impact security changes to AWS Account: $env:AWS_ACCOUNT, press CTRL-C IMMEDIATELY if this is a mistake."
}
#endregion Are you sure (with dire warning)

#region create Security Automation user and group for this script
  Write-Output "`r`nCREATING SPECIAL USER $AccountSetupUser FOR SECURITY AUTOMATION"
  Write-Output "  Creating IAM group $AdministratorsGroupName and user $AccountSetupUser to use for the remainder of this script"
  Write-Output "  GROUP: $AdministratorsGroupName creating... (Always Created, Used for this script to operate)"
  $Results = aws iam create-group --group-name $AdministratorsGroupName | out-string | convertfrom-json
  aws iam attach-group-policy --group-name "$AdministratorsGroupName" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  Write-Output "  USER: $AccountSetupUser creating admin user for remaining account setup (access keys only)..."
  $results = aws iam create-user --user-name $AccountSetupUser | out-string | convertfrom-json
  aws iam add-user-to-group --user-name $AccountSetupUser --group-name $AdministratorsGroupName
  Write-Output "  KEYS: $AccountSetupUser creating keys for user"
  $AccessKeyInfo = aws iam create-access-key --user-name $AccountSetupUser | ConvertFrom-Json

  Start-Sleep 15 #ensure new key is ready

  Write-Output "  Deleting Root Access Key..."
  #aws iam delete-access-key --access-key-id $env:AWS_ACCESS_KEY_ID

  #Set auth info using new keys
  write-output "  Using $AccountSetupUser access keys for remaining operations..."
  $env:AWS_ACCESS_KEY_ID=$Accesskeyinfo.Accesskey.AccessKeyID
  $env:AWS_SECRET_ACCESS_KEY=$Accesskeyinfo.Accesskey.SecretAccessKey
#endregion create Security Automation user and group for this script

Write-Output "`r`nMAKING IAM CHANGES [Benchmark Section 1]"

#region Update Password Policies (Satisfies 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11,1.15)
Write-Output "  Updating Password Policies (Satisfies 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11,1.15)"
aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24
#endregion Update Password Policies (Satisfies 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11,1.15)

Write-Output "`r`nMAKING SAMPLE RESOURCE ADDITIONS"

If (!$Force) {PauseScript}

#region create sample groups and users
Write-Output "  GROUP: $ReadOnlyUsersGroupName creating..."
$Results = aws iam create-group --group-name $ReadOnlyUsersGroupName | out-string | convertfrom-json
aws iam attach-group-policy --group-name $ReadOnlyUsersGroupName --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

Write-Output "  USER: $SampleAdminUser - Creating Sample admin user..."
aws iam create-user --user-name $SampleAdminUser | out-null
aws iam add-user-to-group --user-name $SampleAdminUser --group-name $AdministratorsGroupName
If ($SampleAdminUser) { aws iam create-login-profile --user-name $SampleAdminUser --password "$NewUserPassword" | out-null}

Write-Output "  USER: $SampleReadOnlyUser - Creating Sample Readonly user..."
aws iam create-user --user-name $SampleReadOnlyUser | out-null
aws iam add-user-to-group --user-name $SampleReadOnlyUser --group-name $ReadOnlyUsersGroupName
If ($SampleAdminUser) {aws iam create-login-profile --user-name $SampleReadOnlyUser --password "$NewUserPassword" | out-null}

#endregion create sample groups and users

#region Create CIS Compliant VPC

Write-Output "  VPC: $NewCISVPC_Name - Creating a compliant VPC..."
$vpcdetails = aws ec2 create-vpc --cidr-block "$NewCISVPC_CIDR" --instance-tenancy 'default' | out-string | convertfrom-json
$newvpcid = "$($vpcdetails.vpc.vpcid)"

$secondswaited = 0
DO
{
  Start-Sleep -seconds 5
  $secondswaited += 5
  "    Waited $secondswaited for VPC to be ready so far..."
} While ((aws ec2 describe-vpcs --vpc-ids "$newvpcid" | out-string | convertfrom-json).vpcs.State -ne "available")

aws ec2 create-tags --resources $newvpcid --tags Key=Name,Value="$NewCISVPC_Name"

#endregion Create CIS Compliant VPC

#region Create PUBLIC Subnet

Write-Output "  SUBNET: $NewCISSubnetPublic_CIDR - Creating a compliant public subnet..."
$subnetdetails = aws ec2 create-subnet --vpc-id "$newvpcid" --cidr-block "$NewCISSubnetPublic_CIDR" --availability-zone "$NewCISSubnetPublic_AZ" | out-string | convertfrom-json
$newsubnetid = "$($subnetdetails.subnet.subnetid)"

$secondswaited = 0
DO
{
  Start-Sleep -seconds 5
  $secondswaited += 5
  "    Waited $secondswaited for subnet to be ready so far..."
} While ((aws ec2 describe-subnets --subnet-ids "$newsubnetid" --query Subnets[].State --output text) -ne "available")

aws ec2 create-tags --resources $newsubnetid --tags Key=Name,Value="$NewCISSubnetPublic_NAME"

#Make into a public subnet
aws ec2 modify-subnet-attribute --subnet-id "$newsubnetid" --map-public-ip-on-launch

#endregion Create PUBLIC Subnet

#region Create PRIVATE Subnet
Write-Output "  SUBNET: $NewCISSubnetPrivate_CIDR - Creating a compliant private subnet..."
$subnetdetails = aws ec2 create-subnet --vpc-id "$newvpcid" --cidr-block "$NewCISSubnetPrivate_CIDR" --availability-zone "$NewCISSubnetPrivate_AZ" | out-string | convertfrom-json
$newsubnetid = "$($subnetdetails.subnet.subnetid)"

$secondswaited = 0
DO
{
  Start-Sleep -seconds 5
  $secondswaited += 5
  "    Waited $secondswaited for subnet to be ready so far..."
} While ((aws ec2 describe-subnets --subnet-ids "$newsubnetid" --query Subnets[].State --output text) -ne "available")

aws ec2 create-tags --resources $newsubnetid --tags Key=Name,Value="$NewCISSubnetPrivate_NAME"
#endregion Create PRIVATE Subnet

Write-Output "`r`nMAKING NETWORKING CHANGES [Benchmark Section 4]"

If (!$Force) {PauseScript}

#region Remove Security group Rules [Satisfies 4.4]

Write-Output "  Removing DEFAULT rules from default security groups (satisfies: 4.4 for a NEW account - but not if you have added rules to default groups)"
Write-Output "  Getting complete regions list to operate on..."

$regionlist = @((aws ec2 describe-regions | out-string | convertfrom-json).regions.regionname)

ForEach ($region in $regionlist)
{ #This loop processes the security group changes, whether for everything in the account or just the compliant VPC that was created or just the current region.
    $vpcidlist = @((aws ec2 describe-vpcs --region $region | out-string | convertfrom-json).vpcs.vpcid)
    ForEach ($vpcid in $vpcidlist)
    {
      #Remove the default security group rules
      $VPCDescText = aws ec2 describe-tags --filters "Name=resource-id,Values=$vpcid" "Name=key,Values=Name" --query Tags[].Value --output text
      $VPCDefaultSGDesc = aws ec2 describe-security-groups --region $region --filters Name=vpc-id,Values=$vpcid Name=group-name,Values=default | out-string | convertfrom-json


      $VPCDefaultSGID = $VPCDefaultSGDesc.SecurityGroups.GroupId
      $SGDescText = $VPCDefaultSGDesc.SecurityGroups.GroupName

      "      SG:  $VPCDefaultSGID ($SGDescText) for VPC: $vpcid ($VPCDescText) in REGION: $region - removing *only* DEFAULT rules from DEFAULT security group"
      aws ec2 revoke-security-group-egress --region $region --group-id $VPCDefaultSGID --protocol all --port all --cidr '0.0.0.0/0'
      aws ec2 revoke-security-group-ingress --region $region --group-id $VPCDefaultSGID --protocol all --port all --source-group $VPCDefaultSGID
      aws ec2 create-tags --resources $VPCDefaultSGID --tags Key=Name,Value="DO NOT USE NOR ADD RULES (SecurityAutomation)" --region $region
    }
}

#endregion Remove Security group Rules [Satisfies 4.4]

#region Enable VPC Flow Logging [Satisfies 4.3]

Write-Output "`r`n`r`n  LOGGROUP: $FlowLogsGroup - Adding Log Group for Flow Logging..."

Write-Output "`r`nUPDATING LOGGING [Benchmark Section 2]..."

If (!$Force) {PauseScript}

$FlowLogsGroupDetails = aws logs create-log-group --log-group-name $FlowLogsGroup | out-string | ConvertFrom-Json

Write-Output "    Setting Log Retention Days to: $FlowLogsLogRetentionDays"

aws logs put-retention-policy --log-group-name $FlowLogsGroup --retention-in-days $FlowLogsLogRetentionDays

$FlowLogGroupARN = aws logs describe-log-groups --log-group-name-prefix $FlowLogsGroup --query logGroups[].arn --output text

$FlowLogsRoleTrustPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"@

$FlowLogsRoleTrustPolicyPathName = join-path "$env:temp" 'awsconfig_role_trust_policy.json'
$FlowLogsRoleTrustPolicy | Out-File $FlowLogsRoleTrustPolicyPathName -Encoding ascii

$createdFlowLogsrole = aws iam create-role --role-name $FlowLogsRole --assume-role-policy-document ("file://$FlowLogsRoleTrustPolicyPathName").tolower() | Out-String | ConvertFrom-Json
$createdFlowLogsroleARN = $createdFlowLogsrole.role.arn

Write-Output "  ROLE: $FlowLogsRole - Adding Role Policy for Flow Logging..."

$FlowLogsRolePolicyDoc = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
"@

$FlowLogsRolePolicyPathName = join-path "$env:temp" 'role-policy-document.json'
$FlowLogsRolePolicyDoc | Out-File $FlowLogsRolePolicyPathName -Encoding ascii

aws iam put-role-policy --role-name $FlowLogsRole --policy-name flowlog-policy --policy-document ("file://$FlowLogsRolePolicyPathName").tolower() | Out-null

Write-Output "    Waiting for role to be available..."
Start-Sleep 20

Write-Output "  FLOWLOG: $FlowLogsGroup - Enabling Flow Logging for all VPCs in all Regions..."

$vpcidlist = $null
$regionlist = @((aws ec2 describe-regions | out-string | convertfrom-json).regions.regionname)
ForEach ($region in $regionlist)
{
  $vpcidlist = @((aws ec2 describe-vpcs --region $region | out-string | convertfrom-json).vpcs.vpcid)
  ForEach ($vpcid in $vpcidlist)
  {
    $VPCDescText = aws ec2 describe-tags --filters "Name=resource-id,Values=$vpcid" "Name=key,Values=Name" --query Tags[].Value --output text
    $createflowlogresults = aws ec2 create-flow-logs --traffic-type $FlowLogsFilter --log-group-name $FlowLogsGroup --deliver-logs-permission-arn $createdFlowLogsroleARN --resource-type VPC --resource-ids $vpcid --region $region | out-string | convertfrom-json
    Write-Output "    FLOWLOGID: $($createflowlogresults.FlowLogIds) created for VPC: $vpcid ($VPCDescText) in REGION: $region"
  }

}

#endregion Enable VPC Flow Logging [Satisfies 4.3]


#region CreateCloudTrailLogging (Satisfies 2.1, 2.2, 2.3 and 2.4)

#http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html
#http://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html
#http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail-by-using-the-aws-cli.html


$BucketList = @(aws s3api list-buckets --query 'Buckets[].Name' | out-string | Convertfrom-json)

If
 (($Bucketlist.count -gt 0) -AND ($Bucketlist -inotcontains $CloudTrailBucketName))
{
  Write-Output "  BUCKET: $CloudTrailBucketName - Creating Bucket for CloudTrail"
  aws s3api create-bucket --bucket $CloudTrailBucketName --acl "private" | out-null
}
Else
{
  Write-Output "    Bucket for CloudTrail already exists, name: $CloudTrailBucketName, configuring..."
}

Write-Output "  LOGGROUP: $CloudTrailBucketName - creating log group..."

$LogGroupDetails = aws logs create-log-group --log-group-name $CloudTrailBucketName | out-string | ConvertFrom-Json

Write-Output "    Setting Log Retention Days to: $CloudTrailLogRetentionDays"

aws logs put-retention-policy --log-group-name $CloudTrailBucketName --retention-in-days $CloudTrailLogRetentionDays

$LogGroupARN = aws logs describe-log-groups --log-group-name-prefix $CloudTrailBucketName --query logGroups[].arn --output text

Write-Output "  BUCKET: $CloudTrailBucketName - Applying Bucket Policy..."

$CloudWatchBucketPolicy = @"
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "AWSCloudTrailAclCheck20150319",
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "s3:GetBucketAcl",
			"Resource": "arn:aws:s3:::$CloudTrailBucketName"
		},
		{
			"Sid": "AWSCloudTrailWrite20150319",
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::$CloudTrailBucketName/*",
			"Condition": {
				"StringEquals": {
					"s3:x-amz-acl": "bucket-owner-full-control"
				}
			}
		}
	]
}
"@

$CloudWatchBucketPolicyPathName = join-path "$env:temp" 'cloudwatch_bucket_policy_document.json'
$CloudWatchBucketPolicy | Out-File "$CloudWatchBucketPolicyPathName" -Encoding ascii
$CloudWatchBucketPolicyFileName = ("file://$CloudWatchBucketPolicyPathName").tolower()

Write-Debug "Using file name `"$CloudWatchBucketPolicyFileName`""

aws s3api put-bucket-policy --bucket $CloudTrailBucketName --policy $CloudWatchBucketPolicyFileName | out-null

Write-Output "  ROLE: $CloudTrailRole - Creating Role for CloudTrail..."

$CloudWatchRoleJSON = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"",
      "Effect":"Allow",
      "Principal":{
        "Service":"cloudtrail.amazonaws.com"
      },
      "Action":"sts:AssumeRole"
    }
  ]
}
"@

$AssumeRolePolicyPathName = join-path "$env:temp" 'assume_role_policy_document.json'
$CloudWatchRoleJSON | Out-File $AssumeRolePolicyPathName -Encoding ascii
$AssumeRoleFileName = ("file://$AssumeRolePolicyPathName").tolower()

$createdrole = aws iam create-role --role-name $CloudTrailRole --assume-role-policy-document $AssumeRoleFileName | Out-String | ConvertFrom-Json
$CWRoleARN = $createdrole.role.arn

Write-Output "  ROLE: $CloudTrailRole - Adding Role Policy for CloudTrail..."


$CloudWatchRolePolicyDoc = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailCreateLogStream2014110",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream"
      ],
      "Resource": [
        "$LogGroupARN"
      ]
    },
    {
      "Sid": "AWSCloudTrailPutLogEvents20141101",
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "$LogGroupARN"
      ]
    }
  ]
}
"@

$RolePolicyPathName = join-path "$env:temp" 'role-policy-document.json'
$CloudWatchRolePolicyDoc | Out-File $RolePolicyPathName -Encoding ascii
$RolePolicyFileName = ("file://$RolePolicyPathName").tolower()

aws iam put-role-policy --role-name $CloudTrailRole --policy-name cloudtrail-policy --policy-document $RolePolicyFileName | out-null

Write-Output "  CLOUDTRAIL: $CloudTrailName - Creating Cloud Trail..."

$TrailDetails = aws cloudtrail create-trail --name $CloudTrailName --s3-bucket-name $CloudTrailBucketName --is-multi-region-trail --enable-log-file-validation | out-string | Convertfrom-json

Start-Sleep -seconds 30

$UpdatedTrailDetails = aws cloudtrail update-trail --name $CloudTrailName --cloud-watch-logs-log-group-arn $LogGroupARN --cloud-watch-logs-role-arn $CWRoleARN | out-string | Convertfrom-json

Write-Output "  CLOUDTRAIL: $CloudTrailName - Starting Logging..."

aws cloudtrail start-logging --name $CloudTrailName

$TrailStatus = aws cloudtrail get-trail-status --name $CloudTrailName | out-string | Convertfrom-json

Write-Output "    Checking Status of Trail: $CloudTrailName"
Write-Output "      Logging is Enabled: $($TrailStatus.IsLogging)"
Write-Output "      Logging Started At: $($TrailStatus.TimeLoggingStarted)"

#endregion CreateCloudTrailLogging CreateCloudTrailLogging (Satisfies 2.1, 2.2, 2.3 and 2.4)

#region Encrypt CloudWatch logs [Satisfies 2.7]
Write-Output "  CLOUDTRAIL: $CloudTrailName - Setting log encryption..."

$CloudWatchKMSKeyPolicyDoc = @"
{
  "Version" : "2012-10-17",
  "Id" : "key-consolepolicy-2",
  "Statement" : [ {
    "Sid" : "Enable IAM User Permissions",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::${env:AWS_ACCOUNT}:root"
    },
    "Action" : "kms:*",
    "Resource" : "*"
  }, {
    "Sid" : "Allow access for Key Administrators",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::${env:AWS_ACCOUNT}:user/$AccountSetupUser"
    },
    "Action" : [ "kms:*"],
    "Resource" : "*"
  },
{
  "Sid": "Allow CloudTrail to encrypt logs",
  "Effect": "Allow",
  "Principal": {
    "Service": "cloudtrail.amazonaws.com"
  },
  "Action": "kms:GenerateDataKey*",
  "Resource": "*",
  "Condition": {
    "StringLike": {
      "kms:EncryptionContext:aws:cloudtrail:arn": [
        "arn:aws:cloudtrail:*:${env:AWS_ACCOUNT}:trail/*"
      ]
    }
  }
},
{
  "Sid": "Allow CloudTrail access",
  "Effect": "Allow",
  "Principal": {
    "Service": "cloudtrail.amazonaws.com"
  },
  "Action": "kms:DescribeKey",
  "Resource": "*"
}, {
    "Sid" : "Allow use of the key",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::${env:AWS_ACCOUNT}:role/$CloudTrailRole"
    },
    "Action" : [ "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey" ],
    "Resource" : "*"
  },
  {
    "Sid" : "Allow attachment of persistent resources",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::${env:AWS_ACCOUNT}:role/$CloudTrailRole"
    },
    "Action" : [ "kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant" ],
    "Resource" : "*",
    "Condition" : {
      "Bool" : {
        "kms:GrantIsForAWSResource" : "true"
      }
    }
  }
  ]
}

"@

#$cloudwatchkmskeypolicyString = $cloudwatchkmskeypolicy -replace "`n|`r" -replace '\s+', ' ' -replace '"', '\"'
$CloudWatchKMSKeyPolicyDocPathName = join-path "$env:temp" 'cwkmskey-policy-document.json'
$CloudWatchKMSKeyPolicyDoc | Out-File $CloudWatchKMSKeyPolicyDocPathName -Encoding ascii
$CloudWatchKMSKeyPolicyDocFileName = ("file://$CloudWatchKMSKeyPolicyDocPathName").tolower()

$kmskeysinfo = aws kms create-key --policy $CloudWatchKMSKeyPolicyDocFileName --description "KMS Key for Cloudwatch Encryption" | out-string | convertfrom-json

aws cloudtrail update-trail --name "$CloudTrailName" --kms-key-id $kmskeysinfo.keymetadata.keyid | out-null

#endregion Encrypt CloudWatch logs [Satisfies 2.7]

#region Setup CloudWatch Bucket Logging (Satisfies 2.6)
Write-Output "  BUCKET: $CloudTrailBucketName - Setting up Bucket Logging"

$CloudWatchBucketLoggingPolicyDoc = @"
{
  "LoggingEnabled": {
    "TargetBucket": "$CloudTrailBucketName",
    "TargetPrefix": ""
  }
}
"@

$CloudWatchBucketLoggingPolicyDocPathName = join-path "$env:temp" 'cwbucketlogging-policy-document.json'
$CloudWatchBucketLoggingPolicyDoc | Out-File $CloudWatchBucketLoggingPolicyDocPathName -Encoding ascii
$CloudWatchBucketLoggingPolicyDocFileName = ("file://$CloudWatchBucketLoggingPolicyDocPathName").tolower()

aws s3api put-bucket-acl --bucket $CloudTrailBucketName --grant-write 'URI="http://acs.amazonaws.com/groups/s3/LogDelivery"' --grant-read-acp 'URI="http://acs.amazonaws.com/groups/s3/LogDelivery"'

aws s3api put-bucket-logging --bucket $CloudTrailBucketName --bucket-logging-status $CloudWatchBucketLoggingPolicyDocFileName | out-null

#endregion Setup CloudWatch Bucket Logging (Satisfies 2.6)

#region Enable AWS Config (satisfies 2.5)

#http://docs.aws.amazon.com/config/latest/developerguide/gs-cli-prereq.html
#http://docs.aws.amazon.com/config/latest/developerguide/gs-cli-subscribe.html


Write-Output "  Updating AWS Config Logging"

Write-Output "  TOPIC: $AWSConfigSNSTopic - Creating SNS Topic for AWS Config"

$BucketList = @(aws s3api list-buckets --query 'Buckets[].Name' | out-string | Convertfrom-json)
If (($Bucketlist.count -gt 0) -AND ($Bucketlist -inotcontains $CloudTrailBucketName))
{
  Write-Output "  BUCKET: $AWSConfigBucketName - Creating Bucket for AWS Config"
  aws s3api create-bucket --bucket $AWSConfigBucketName --acl "private" | out-null
}
Else
{
  Write-Output "  Bucket for CloudTrail already exists, name: $AWSConfigBucketName, configuring..."
}


$createdAWSConfigtopic = aws sns create-topic --name $AWSConfigSNSTopic | out-string | convertfrom-json
$createdAWSConfigtopicARN = $createdAWSConfigtopic.TopicARN

Write-Output "  BUCKET: $AWSConfigBucketName - Adding Role policy for AWS Config"

$AWSConfigBucketPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::$AWSConfigBucketName"
    },
    {
      "Sid": " AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$AWSConfigBucketName/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
"@

$AWSConfigBucketPolicyDocPathName = join-path "$env:temp" 'awsconfig_bucket_policy_document.json'
$AWSConfigBucketPolicy | Out-File $AWSConfigBucketPolicyDocPathName -Encoding ascii
$AWSConfigBucketPolicyFileName = ("file://$AWSConfigBucketPolicyDocPathName").tolower()

aws s3api put-bucket-policy --bucket $AWSConfigBucketName --policy $AWSConfigBucketPolicyFileName | out-null

Write-Output "  ROLE: $AWSConfigRole - Creating Role for AWS Config..."

$AWSConfigRoleTrustPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":"",
      "Effect":"Allow",
      "Principal":{
        "Service":"config.amazonaws.com"
      },
      "Action":"sts:AssumeRole"
    }
  ]
}
"@

$AWSConfigRoleTrustPolicyPathName = join-path "$env:temp" 'awsconfig_role_trust_policy.json'
$AWSConfigRoleTrustPolicy | Out-File $AWSConfigRoleTrustPolicyPathName -Encoding ascii
$AWSConfigRoleTrustPolicyFileName = ("file://$AWSConfigRoleTrustPolicyPathName").tolower()

$createdAWSConfigrole = aws iam create-role --role-name $AWSConfigRole --assume-role-policy-document $AWSConfigRoleTrustPolicyFileName | Out-String | ConvertFrom-Json
$createdAWSConfigroleARN = $createdAWSConfigrole.role.arn

Write-Output "  ROLE: $AWSConfigRole - Adding role policy for AWS Config..."

$AWSConfigRolePolicy = @"
{
  "Version": "2012-10-17",
  "Statement":
   [
     {
       "Effect": "Allow",
       "Action": ["s3:PutObject"],
       "Resource": ["arn:aws:s3:::$AWSConfigBucketName/AWSLogs/$env:AWS_ACCOUNT/*"],
       "Condition":
        {
          "StringLike":
            {
              "s3:x-amz-acl": "bucket-owner-full-control"
            }
        }
     },
     {
       "Effect": "Allow",
       "Action": ["s3:GetBucketAcl"],
       "Resource": "arn:aws:s3:::$AWSConfigBucketName"
     },
     {
      "Effect":"Allow",
      "Action":"sns:Publish",
      "Resource":"$createdAWSConfigtopicARN"
     }
  ]
  }
"@

$AWSConfigRolePolicyPathName = join-path "$env:temp" 'awsconfig_role_policy.json'
$AWSConfigRolePolicy | Out-File $AWSConfigRolePolicyPathName -Encoding ascii
$AWSConfigRolePolicyFileName = ("file://$AWSConfigRolePolicyPathName").tolower()

aws iam put-role-policy --role-name $AWSConfigRole --policy-name awsconfig-policy --policy-document $AWSConfigRolePolicyFileName

Write-Output "    Waiting for role to be available..."
Start-Sleep 20

Write-Output "    Adding Standard AWS AWSConfigRole Managed policy to role: $AWSConfigRole..."
aws iam attach-role-policy --role-name $AWSConfigRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSConfigRole

Write-Output "  TOPIC: $AWSConfigSNSTopic - Updating SNS Policy for topic..."

$SNSPolicy = @"
{
  "Id": "Policy1415489375392",
  "Statement": [
    {
      "Sid": "AWSConfigSNSPolicy20150201",
      "Action": [
        "SNS:Publish"
      ],
      "Effect": "Allow",
      "Resource": "$createdAWSConfigtopicARN",
      "Principal": {
        "Service": [
          "config.amazonaws.com"
        ]
      }
    }
  ]
}
"@

$SNSPolicyString = $SNSPolicy -replace "`n|`r" -replace '\s+', ' ' -replace '"', '\"'

aws sns set-topic-attributes --topic-arn $createdAWSConfigtopicARN --attribute-name "Policy" --attribute-value "$SNSPolicyString" | out-null

Write-Output "  TOPIC: $AWSConfigSNSTopic - Subscribing $AWSConfigBucketName bucket to SNS Topic..."

#http://docs.aws.amazon.com/config/latest/developerguide/gs-cli-subscribe.html

aws configservice subscribe --s3-bucket $AWSConfigBucketName --sns-topic $createdAWSConfigtopicARN --iam-role "arn:aws:iam::$($env:AWS_ACCOUNT):role/$AWSConfigRole" | out-null

$ConfigServiceStatus = aws configservice describe-delivery-channels | out-string | convertfrom-json #verify AWS Config is on
Write-Output "    Confirmed SNS subscription: $($ConfigServiceStatus.DeliveryChannel.snsTopicARN)"
#endregion Enable AWS Config (satisfies 2.5)

#region Enable KMS Key Rotation (satisfies 2.8)

Write-Output "  Setting up KMS Key rotation for encrypted logs..."

$kmskeys = @(aws kms list-keys | Convertfrom-json)

Foreach ($kmskey in @($kmskeys.keys.keyid))
{
  If (!([bool](aws kms get-key-rotation-status --key-id $kmskey | convertfrom-json).keyrotationenabled))
  {
    aws kms enable-key-rotation --key-id $kmskey
    If ($lastexitcode -gt 0)
    {
      If ($Error[0].exception -match 'AccessDeniedException')
      {
        Write-Warning "Current access level does not allow changing of KMS key id: $kmskey"
      }
      Else
      {
        Write-Warning "An error occured while trying to change of KMS key id: $kmskey"
        Write-Warning $Error[0].exception
      }
    }
    Else
    {
      Write-Output "    Non-compliant KMS Key: $kmskey now has rotation set."
    }
  }
}
#endregion Enable KMS Key Rotation (satisfies 2.8)


#region Enable Security Monitoring Alerts (Satisfied 3.1-3.14)
cls
Write-Output "`r`nMAKING MONITORING CHANGES [Benchmark Section 3]"

If (!$Force) {PauseScript}

$createdAWSMetricAlarmtopic = aws sns create-topic --name "$SNSTopicForSecurityAlerts" | out-string | convertfrom-json
$createdAWSMetricAlarmtopicARN = $createdAWSMetricAlarmtopic.TopicARN

$subscriptionresults = aws sns subscribe --topic-arn $createdAWSMetricAlarmtopicARN --protocol email --notification-endpoint "$EmailforSecurityAlerts" | out-string | convertfrom-json

Write-Output "  Subscription created for email $EmailForSecurityAlerts, status is: $($subscriptionresults.SubscriptionARN)`r`n"

Write-Output "  Adding metric filters and alerts:"

$SecurityMetricsAndAlarmList = @{
  'CIS v1.0r3.01 - Unauthorized API Call' = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
  'CIS v1.0r3.02 - Signin Without MFA'    = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
  'CIS v1.0r3.03 - Root Account Was Used' = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
  'CIS v1.0r3.04 - I AM Policy Changed'   = '{ ($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}'
  'CIS v1.0r3.05 - CloudTrail Config Changed' = '{ ($.eventName=CreateTrail)||($.eventName=UpdateTrail)||($.eventName=DeleteTrail)||($.eventName=StartLogging)||($.eventName=StopLogging) }' 
  'CIS v1.0r3.06 - Console Logon Failure'     = '{ ($.eventName=ConsoleLogin) && ($.errorMessage = "Failed*" ) && ($.errorMessage = "*authentication" ) }'
  'CIS v1.0r3.07 - KMS Key Disabled or Deleted' = '{ ($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }'
  'CIS v1.0r3.08 - S3 Bucket Policy Changed'    = '{ ($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication)) }'
  'CIS v1.0r3.09 - AWS Config Changed'          = '{ ($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }'
  'CIS v1.0r3.10 - Security Group Changed'     = '{ ($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}'
  'CIS v1.0r3.11 - Network Access Control List (NACL) Changed' = '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation) }' 
  'CIS v1.0r3.12 - Network Gateway was Changed' = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway) }' 
  'CIS v1.0r3.13 - Route Table was Changed' = '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName=DisassociateRouteTable) }' 
  'CIS v1.0r3.14 - VPC was Changed' = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
}


ForEach ($MetricAlarmName in ($SecurityMetricsAndAlarmList.GetEnumerator() | sort-object -Property Name)) {
  Write-Output "  `"$($MetricAlarmName.name)`" - Adding Log Metric and Security Alert"
  #aws logs delete-metric-filter --log-group-name $CloudTrailBucketName --filter-name $($MetricAlarmName.name)
  aws logs put-metric-filter --log-group-name "$CloudTrailBucketName" --filter-name "$($MetricAlarmName.name)" --metric-transformations metricName="$(($MetricAlarmName.name))",metricNamespace="$MetricNameSpaceforBenchmark",metricValue=1 --filter-pattern "$($MetricAlarmName.Value)"
  aws cloudwatch put-metric-alarm --alarm-name "$($MetricAlarmName.name)" --metric-name "$($MetricAlarmName.name)" --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace "$MetricNameSpaceforBenchmark" --alarm-actions "$createdAWSMetricAlarmtopicARN"
}

#endregion Enable Security Monitoring Alerts (Satisfied 3.1-3.14)
