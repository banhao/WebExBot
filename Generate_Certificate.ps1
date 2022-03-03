<#PSScriptInfo

.VERSION 2.00

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR HAO BAN/hao.ban@ehealthsask.ca/banhao@gmail.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

.PRIVATEDATA

.SYNOPSIS

.EXAMPLE

.DESCRIPTION 
	Creation Date:  <02/10/2022>

.Parameter

#> 

#-------------------------------------------------------------------------------------------------------------------------------------------------------
#variables
$PolicyFile = $Args[0]
$ENVIRONMENT = $Args[1]
$CN = Get-Content .\$PolicyFile | findstr "Subject" | %{ $_.Split(',')[0]; } | %{ $_.Split('=')[2]; }
$Email = $(Get-Content .\$PolicyFile | findstr "Subject" | %{ $_.Split('=')[-1]; }).Trim('"')
$CertificateTemplate = $(Get-Content .\$PolicyFile | findstr "CertificateTemplate" | %{ $_.Split('=')[1]; }).trim()
$FriendlyName = $(Get-Content .\$PolicyFile | findstr "FriendlyName" | %{ $_.Split('=')[1]; }).trim()
$Folder = "$PSScriptRoot\Certificates"
$CSRFile = $PolicyFile + ".csr"
if (-not (Test-Path -Path $Folder)){
	 New-Item -Path $Folder -ItemType "directory"
}
Certreq.exe -New .\$PolicyFile $Folder\$CSRFile
Start-Sleep -s 3
if( test-path $Folder\$CSRFile ){
	Write-OutPut $CSRFile "generated successfully" >> .\Certificate_output.log 
### Generate the Certificate.
	$CertFile = $PolicyFile + ".cer"
	if ($ENVIRONMENT -eq 'PROD' -and $CertificateTemplate -eq 'ExternalClientAuth4yearOffline'){
		$CAServer = ""
	}
	elseif($ENVIRONMENT -eq 'PROD' -and ($CertificateTemplate -eq 'Client1' -or $CertificateTemplate -eq 'Client2')){
		$CAServer = ""
	}
	elseif($ENVIRONMENT -eq 'UAT'){
		$CAServer = ""
	}
	$RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CertificateTemplate" -config $CAServer $Folder\$CSRfile $Folder\$CertFile
	$RequestId = $RequestIdOutPut[0] | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
	Start-Sleep -s 1
	if( test-path $Folder\$CertFile ){ 
		Write-OutPut $CertFile "generated successfully. Request ID: " $RequestId  "on" $CAServer >> .\Certificate_output.log 		
		$Thumbprint = $($(certutil $Folder\$CertFile)[-4] -split ":")[1] | foreach{ $_.ToString().Trim()} 
		$Expiry = $($(certutil $Folder\$CertFile)[17] -split " ")[2] | foreach{ $_.ToString().Trim()}
### Import the Certificate 
		Import-Certificate -FilePath $Folder\$CertFile -CertStoreLocation cert:\CurrentUser\My
		Start-Sleep -s 1
### Export the Certificate
		$PFXFile = $FriendlyName + ".pfx"
		$PASSWORD = -join ((48..57) + (97..122) | Get-Random -Count 12 | % {[char]$_})
		$SecurePASSWD = ConvertTo-SecureString -String $PASSWORD -Force -AsPlainText
		Get-ChildItem -Path cert:\CurrentUser\my\$Thumbprint | Export-PfxCertificate -FilePath $Folder\$PFXFile -Password $SecurePASSWD
		Start-Sleep -s 1
		if( test-path $Folder\$PFXFile ){ 
			Write-OutPut $PFXFile "generated successfully" >> .\Certificate_output.log
			$EmailSubject = "Request #" + $RequestId + ": Certificate(s) from eHS to Be Installed for [*" + $CN + "*] on" + $CAServer
			Send-MailMessage -SmtpServer relay-partner.ehealthsask.ca -To $Email -From SecurityAssistantBot@ehealthsask.ca -Subject $EmailSubject -Body $PASSWORD -Attachments $Folder\$PFXFile
		}else{ Write-OutPut "Didn't generate the PFX File successfully" >> .\Certificate_output.log }
	}else{ Write-OutPut "Didn't generate the Certificate successfully" >> .\Certificate_output.log }
}else{ Write-OutPut "Didn't generate the CSR File successfully" >> .\Certificate_output.log }
Write-OutPut "---------------------------------------------------------" >> .\Certificate_output.log
del .\$PolicyFile
