$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$user = $CurrentUser.split("\")[1]

Write-Host "Hello! This script is designed to harden any Windows machine for Cyberpatriot purposes."
Write-Host "Make sure you have already completed the forensics questions! This script changes group policy, which can make solving those questions impossible."
Write-Host "One more thing - if you're on Windows Server, there might be some things in the README that go against what this script does (i.e. blocking ports, remote desktop, etc.), so be mindful of that and fix anything that makes you lose points."
Read-Host "Press Enter to acknowledge the above statements and continue."

Write-Host "Changing local security policies:"
secedit /configure /db c:\windows\security\local.sdb /cfg C:\Users\$user\Desktop\Script\security-policy.inf

Write-Host "Changing group policy for this computer:"
Copy-Item -Path C:/Users/$user/Desktop/Script/GroupPolicy -Destination C:/Windows/system32 -Recurse -Force
gpupdate /force

Write-Host "Cleaning hosts file:"
Copy-Item -Path C:/Users/$user/Desktop/Script/hosts -Destination C:/Windows/system32/drivers/etc -Force

Write-Host "Turning on firewall and shutting off some ports (you will still have internet access, no worries):"
try
{
	Get-Service -DisplayName "DHCP Client" -ErrorAction Stop | Set-Service -StartupType Automatic -ErrorAction Stop
	Get-Service -DisplayName "DHCP Client" -ErrorAction Stop | Start-Service -ErrorAction Stop
}
catch
{
	Write-Host "Looks like DHCP Client was either already running or unavailable. Might want to check that out."
}

try
{
	Get-Service -DisplayName "Windows Firewall" -ErrorAction Stop | Set-Service -StartupType Automatic -ErrorAction Stop
	Get-Service -DisplayName "Windows Firewall" -ErrorAction Stop | Start-Service -ErrorAction Stop
}
catch
{
	Write-Host "Looks like the Windows Firewall service was either already running or does not exist (which is fine)."
}

NetSh Advfirewall set allprofiles state on
Set-NetFirewallProfile -Name Public –DefaultInboundAction Block
Set-NetFirewallProfile -Name Private –DefaultInboundAction Block
Set-NetFirewallProfile -Name Domain –DefaultInboundAction Block

#Set-NetFirewallProfile -Name Public –DefaultOutboundAction Block
#Set-NetFirewallProfile -Name Private –DefaultOutboundAction Block
#Set-NetFirewallProfile -Name Domain –DefaultOutboundAction Block
#
#New-NetFirewallRule -DisplayName "Allow Firefox" -Direction Outbound -Program "C:/Program Files/Mozilla Firefox/firefox.exe" -Action Allow

Set-NetFirewallProfile -Name Public –DefaultOutboundAction Allow
Set-NetFirewallProfile -Name Private –DefaultOutboundAction Allow
Set-NetFirewallProfile -Name Domain –DefaultOutboundAction Allow

New-NetFirewallRule -DisplayName "Block SSH" -Direction Outbound -LocalPort 22 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Outbound -LocalPort 23 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block RPC TCP" -Direction Outbound -LocalPort 135 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block RPC UDP" -Direction Outbound -LocalPort 135 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block SNMP" -Direction Outbound -LocalPort 161-162 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block LDAP TCP" -Direction Outbound -LocalPort 389 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block LDAP UDP" -Direction Outbound -LocalPort 389 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block RDP" -Direction Outbound -LocalPort 3389 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block RPC TCP" -Direction Outbound -LocalPort 135 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block RPC UDP" -Direction Outbound -LocalPort 135 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS TCP" -Direction Outbound -LocalPort 137-139 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block RPC UDP" -Direction Outbound -LocalPort 137-139 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block SMB" -Direction Outbound -LocalPort 445 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Syslog" -Direction Outbound -LocalPort 445 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block IRC" -Direction Outbound -LocalPort 6660-6669 -Protocol TCP -Action Block
$ftp = Read-Host "Does the README require FTP protocol (check it)? Enter Y or N."
while ($addUser -ne 'Y' -and $addUser -ne 'N')
{
	$addUser = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
if ($ftp -eq 'N')
{
	New-NetFirewallRule -DisplayName "Block FTP" -Direction Outbound -LocalPort 20-21 -Protocol UDP -Action Allow
}

Set-NetFireWallProfile -Profile Domain -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 20000 -LogFileName "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
Set-NetFireWallProfile -Profile Private -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 20000 -LogFileName "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
Set-NetFireWallProfile -Profile Public -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 20000 -LogFileName "%SystemRoot%\System32\logfiles\firewall\publicfw.log"

Set-NetFirewallProfile -Name Domain -NotifyOnListen False
Set-NetFirewallProfile -Name Private -NotifyOnListen False
Set-NetFirewallProfile -Name Public -NotifyOnListen False

reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" /v AllowLocalPolicyMerge /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" /v AllowLocalPolicyMerge /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" /v AllowLocalPolicyMerge /t REG_DWORD /d 0 /f

Write-Host "Turning off guest account:"
net user guest /active:no

Write-Host "Turning off default admin account:"
net user Administrator /active:no

#Write-Host "Installing python (necessary for user account control):"
#./python-3.10.1-amd64.exe
#Read-Host "Press Enter to continue"

#pip install bs4
#python getData.py $user
Write-Host "This next step will take care of user/admin stuff for you."
Write-Host "HOWEVER, this requires that you have filled out the users.txt file and the admins.txt file with the list of users and admins (line by line with just names)."
Read-Host "Press Enter to confirm that everything is set up and you are ok to proceed."

Write-Host "Deleting all unauthorized users and fixing group of admins:"
$userData = @(Get-Content -Path C:/Users/$user/Desktop/Script/users.txt)
$adminData = @(Get-Content -Path C:/Users/$user/Desktop/Script/admins.txt)
$userList = @(Get-WmiObject -Class Win32_UserAccount | Format-wide -property name -column 1
)
$admins = net localgroup administrators
$admins = @($admins[6..($admins.Length-3)])
foreach ($actual in $userList)
{
	if ($actual -eq "WDAGUtilityAccount" -or $actual -eq "DefaultAccount" -or $actual -eq "Administrator" -or $actual -eq "Guest" -or $actual -eq $user){
		continue
	}
	if (-not (($userData -match $actual) -or (-not($adminData -match $actual))))
	{
		Remove-LocalUser -Name $actual
	}
	if (($userData -match $actual ) -and (-not ($adminData -match $actual)))
	{
		Remove-LocalGroupMember -Group "Administrators" -Member $actual
	}
	if (($adminData -match $actual) -and (-not ($admins -match $actual)))
	{
		Add-LocalGroupMember -Group "Administrators" -Member $actual
	}
}

<#$deleteUser = Read-Host "Would you like to delete a user? Enter Y or N."
while ($deleteUser -ne 'Y' -and $deleteUser -ne 'N')
{
	$deleteUser = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($deleteUser -eq 'Y'){
	Write-Host "Here are a list of users on this computer:"
	Get-LocalUser | Write-Host
	$userToDelete = Read-Host "Type in the name of the user you wish to erase from this world."
	Write-Host "Deleting..."
	Remove-LocalUser -Name $userToDelete
	$deleteUser = Read-Host "Would you like to delete another user? Enter Y or N."
	while ($deleteUser -ne 'Y' -and $deleteUser -ne 'N')
	{
		$deleteUser = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Aw man..."
#>
$addUser = Read-Host "Would you like to add a user? Enter Y or N."
while ($addUser -ne 'Y' -and $addUser -ne 'N')
{
	$addUser = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($addUser -eq 'Y'){
	Write-Host "Here are a list of users on this computer:"
	Get-LocalUser | Write-Host
	$userToAdd = Read-Host "Type in the name of the user you wish to add to this world."
	$userPass = Read-Host "What is their password going to be? It's going to be changed later on, so just type a bunch of characters, numbers, and special characters to bypass the password rules." -AsSecureString
	$userFull = Read-Host "What is their full name?"
	$userDesc = Read-Host "Provide a short description."
	Write-Host "Adding..."
	New-LocalUser $userToAdd -Password $userPass -FullName $userFull -Description $userDesc
	$addUser = Read-Host "Would you like to add another user? Enter Y or N."
	while ($addUser -ne 'Y' -and $addUser -ne 'N')
	{
		$addUser = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Aw man..."

$deleteGroup = Read-Host "Would you like to delete a group? Enter Y or N."
while ($deleteGroup -ne 'Y' -and $deleteGroup -ne 'N')
{
	$deleteGroup = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($deleteGroup -eq 'Y'){
	Write-Host "Here are a list of groups on this computer:"
	Get-LocalGroup | Write-Host
	$groupToDelete = Read-Host "Type in the name of the group you wish to erase from this world."
	Write-Host "Deleting..."
	Remove-LocalGroup -Name $groupToDelete
	$deleteGroup = Read-Host "Would you like to delete another group? Enter Y or N."
	while ($deleteGroup -ne 'Y' -and $deleteGroup -ne 'N')
	{
		$deleteGroup = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Aw man..."

$addGroup = Read-Host "Would you like to add a new group? Enter Y or N."
while ($addGroup -ne 'Y' -and $addGroup -ne 'N')
{
	$addGroup = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($addGroup -eq 'Y'){
	$groupToAdd = Read-Host "Type in the name of the group you wish to add to this world."
	Write-Host "Adding..."
	New-LocalGroup -Name $groupToAdd
	$addGroup = Read-Host "Would you like to add another group? Enter Y or N."
	while ($addGroup -ne 'Y' -and $addGroup -ne 'N')
	{
		$addGroup = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Aw man..."

$remove = Read-Host "Would you like to remove a user from a group? Enter Y or N."
while ($remove -ne 'Y' -and $remove -ne 'N')
{
	$remove = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($remove -eq 'Y'){
	Write-Host "Here are a list of groups on this computer:"
	Get-LocalGroup | Write-Host
	$group = Read-Host "Specify the group the user is in:"
	Write-Host "Here are all the members of that group:"
	Get-LocalGroupMember -Group $group | Write-Host
	$removeUser = Read-Host "Type in the name of the user to be banished forever."
	Write-Host "Removing..."
	Remove-LocalGroupMember -Group $group –Member $removeUser
	$remove = Read-Host "Would you like to remove another user from a group? Enter Y or N."
	while ($remove -ne 'Y' -and $remove -ne 'N')
	{
		$remove = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Aw man..."

$add = Read-Host "Would you like to add a user to a group? Enter Y or N."
while ($add -ne 'Y' -and $add -ne 'N')
{
	$add = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($add -eq 'Y'){
	Write-Host "Here are a list of groups on this computer:"
	Get-LocalGroup | Write-Host
	$groupOfAdd = Read-Host "Specify the group the user should be put in:"
	Write-Host "Here are all the members of that group:"
	Get-LocalGroupMember -Group $group | Write-Host
	$addMe = Read-Host "Type in the name of the user to be added."
	Write-Host "Adding..."
	Add-LocalGroupMember -Group $groupOfAdd –Member $addMe
	$add = Read-Host "Would you like to ad another user to a group? Enter Y or N."
	while ($add -ne 'Y' -and $add -ne 'N')
	{
		$add = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Aw man..."

$addTo = Read-Host "Would you like to make a user an administrator? Enter Y or N."
while ($addTo -ne 'Y' -and $addTo -ne 'N')
{
	$addTo = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($addTo -eq 'Y'){
	Write-Host "Here are a list of local admins on this computer:"
	$members = net localgroup administrators
	$members[6..($members.Length-3)] | Write-Host
	$userAddToGroup = Read-Host "Type in the name of the user to be elevated."
	Write-Host "Adding..."
	Add-LocalGroupMember -Group "Administrators" –Member $userAddToGroup
	$addTo = Read-Host "Would you like to elevate another user? Enter Y or N."
	while ($addTo -ne 'Y' -and $addTo -ne 'N')
	{
		$addTo = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Fine..."

Write-Host "Changing all users' passwords to `"This1Is2A3Secure4Pass5{';/}99`" for security (don't worry, yours won't be changed):"
$arr = @(Get-LocalUser | Select-Object Name)
foreach ($use in $arr) {
	$use = "" + $use
	$actual = $use.Substring($use.indexOf('=')+1,($use.indexOf('}')-1)-$use.indexOf('='))
	if ($actual -eq "WDAGUtilityAccount" -or $actual -eq "DefaultAccount" -or $actual -eq "Administrator" -or $actual -eq "Guest" -or $actual -eq $user){
		continue
	}
	$Secure_String_Pwd = ConvertTo-SecureString "`"This1Is2A3Secure4Pass5{';/}99`"" -AsPlainText -Force
	$actual | Set-LocalUser -Password $Secure_String_Pwd 
}

Write-Host "Turning on auditing for all cases:"
auditpol /restore /file:C:/Users/$user/Desktop/Script/Audit.ini

Write-Host "Turning on automatic updaes:"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 0 /f

Write-Host "Turning off C Drive sharing (if not shared, it should say 'This shared resource does not exist'):"
net share C /delete

$shareAsk = Read-Host "Would you like to disable a folder share? Enter Y or N."
while ($shareAsk -ne 'Y' -and $shareAsk -ne 'N')
{
	$shareAsk = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($shareAsk -eq 'Y'){
	Write-Host "Here are a list of folder shares on this computer:"
	net share | Write-Host
	Write-Host "DO NOT DELETE THE C$, IPC$, OR ADMIN$ SHARES!!!!!!"
	$shareDelete = Read-Host "Type in the name of the share to be disabled."
	Write-Host "Deleting..."
	net share $shareDelete /delete
	$shareAsk = Read-Host "Would you like to disable another folder share? Enter Y or N."
	while ($shareAsk -ne 'Y' -and $shareAsk -ne 'N')
	{
		$shareAsk = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Fine..."

Write-Host "Sniffing out any .mp3 files (this may take a little bit):"
Get-ChildItem C:\ *.mp3 -file -ea silent -recurse
#Write-Host "Sniffing out any .jpg files (this may take a little bit):"
#Get-ChildItem C:\ *.jpg -file -ea silent -recurse
$findEnten = Read-Host "Would you like to sniff out some more unwanted files? Enter Y or N."
while ($findEnten -ne 'Y' -and $findEnten -ne 'N')
{
	$findEnten = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
while ($findEnten -eq 'Y')
{
	$exten = Read-Host "Type in the file extension you would like to search for, NO PUNCTUATION (ex. 'mp3','exe'):"
	Write-Host "Searching..."
	Get-ChildItem C:\ *.$exten -file -ea silent -recurse
	Write-Host "Above is some information about the files you requested including their location, if there were any files found. Use them for forensics (though you should have done that already!) or delete them."
	$findEnten = Read-Host "Would you like to sniff out some more unwanted files? Enter Y or N."
	while ($findEnten -ne 'Y' -and $findEnten -ne 'N')
	{
		$findEnten = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "No? Ok then..."

$remoteOff = Read-Host "Would you like to turn off Remote Desktop? IF YOU ARE ON WINDOWS SERVER, YOU MOST LIKELY SHOULDN'T. Enter Y or N."
while ($remoteOff -ne 'Y' -and $remoteOff -ne 'N')
{
	$remoteOff = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}

if ($remoteOff -eq 'Y')
{

Write-Host "Turning off Remote Desktop:"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
$services = Get-Content -Path "C:\Users\$user\Desktop\Script\RemoteDesktop.txt"
foreach ($service in $services)
{
	try
	{
		Get-Service -DisplayName $service -ErrorAction Stop | Set-Service -StartupType Disabled -ErrorAction Stop
		Get-Service -DisplayName $service -ErrorAction Stop | Stop-Service -Force -ErrorAction Stop
		Write-Host "Service disabled successfully."
	}

	catch
	{
		Write-Host "The service $service was already disabled or does not exist."
	}
}

}

Write-Host "Disabling unnecessary services:"
$services = Get-Content -Path "C:\Users\$user\Desktop\Script\DisableServices.txt"
foreach ($service in $services)
{
	try
	{
		Get-Service -DisplayName $service -ErrorAction Stop | Set-Service -StartupType Disabled -ErrorAction Stop
		Get-Service -DisplayName $service -ErrorAction Stop | Stop-Service -Force -ErrorAction Stop
		Write-Host "Service disabled successfully."
	}

	catch
	{
		Write-Host "The service $service was already disabled or does not exist."
	}
}

$disable = Read-Host "Would you like to manually disable a service? Enter Y or N."
while ($disable -ne 'Y' -and $disable -ne 'N')
{
	$disable = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
if ($disable -eq 'Y'){
	Write-Host "Here is a list of services in alphabetical order. You'll need this to type in the exact service name."
	Get-Service | Sort-Object -Property Name | Select-Object Name | Write-Host
}
while ($disable -eq 'Y'){
	$stopService = Read-Host "What service would you like to stop?"
	Write-Host "Stopping..."
	Get-Service -DisplayName $stopService | Stop-Service
	$disable = Read-Host "Would you like to disable another service? Enter Y or N."
	while ($disable -ne 'Y' -and $disable -ne 'N')
	{
		$disable = Read-Host "Invalid response. Enter either Y or N."
	}
}
Write-Host "No? Fine..."

#Write-Host "Installing Chocolatey, a command line tool to uninstall/update programs:"
#Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
#Read-Host "Press Enter to continue:"


$uninstall = Read-Host "Would you like to uninstall a program? Enter Y or N."
while ($uninstall -ne 'Y' -and $uninstall -ne 'N')
{
	$uninstall = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
}
if ($uninstall -eq 'Y'){
	Write-Host "Here are a list of programs in alphabetical order. You'll need this to type in the exact program name."
	$apps = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | 

	ForEach-Object {Get-ItemProperty $_.PsPath} | 

	Where-Object {$_.Displayname -and ($_.Displayname -match ".*")} | 

	Sort-Object Displayname | Select-Object DisplayName, Publisher | Write-Output

	Write-Host $apps
}
while ($uninstall -eq 'Y'){
	$deleteApp = Read-Host "What program would you like to uninstall?"
	Write-Host "Uninstalling..."
	$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq $deleteApp}
	$MyApp.Uninstall()
	$uninstall = Read-Host "Would you like to uninstall another program? Enter Y or N."
	while ($uninstall -ne 'Y' -and $uninstall -ne 'N')
	{
		$uninstall = Read-Host "Invalid response. Enter either uppercase Y or uppercase N."
	}
}
Write-Host "What? But I wanted to delete System32! Just kidding..."

Write-Host "Installing Malwarebytes, a pretty cool antivirus that can help you find sketchy files:"
./MBSetup-10789.10789-consumer.exe
Read-Host "Press Enter to continue"

Write-Host "Updating Mozilla Firefox to the latest version:"
./Update-MozillaFirefox.ps1
Read-Host "Press Enter to continue"

Write-Host "That's all for now, good luck on Ubuntu! Also, this script probably won't cover everything (it can't update apps), so make sure to do some work yourself!"
set-executionpolicy restricted -Force