# CyPat-Script
This is Team 14-1985's Windows Cyberpatriot script. Do not claim otherwise (or else!!!). Code made by Jai Nagaraj.

This folder contains a .ps1 file (the script), a .inf file (no, it's not an audio file; those are the security settings to import), an audit policy file, and group policy settings. Make sure to read the notes at the bottom of the page before continuing! After that, follow these steps to use the script:

Download this folder to your host computer
Open the VM (obviously)
Copy and paste the folder from your host computer to the DESKTOP of the VM.
In the searchbar of the VM, type "Powershell", right-click on the first option (should be "Windows Powershell''), and select "Run as administrator"
Type "get-executionpolicy" without the quotes. If the console prints out "remotesigned", "allsigned", "bypass", or "unrestricted", skip step 5. But if not…
Type "set-executionpolicy remotesigned" (again, never with quotes), press Enter, then type "Y", and press Enter again.
Make sure you know your username (if not, either read the README of the VM or type "whoami" and read the name after the backslash); you'll need it! Type "cd C:/Users/"your username goes here but without the quotes"/Desktop/Script. I shouldn't need to explain that you shouldn't literally type in "your username goes here but without the quotes", but instead type in the username
Finally, type "./CypatScript_v'whatever number version this script is on'"  (the current version is CypatScript_v7 as of Dec. 28, 2022), and you're good to go!

NOTES AND REMINDERS:

MAKE SURE TO DO FORENSICS BEFORE RUNNING THE SCRIPT!!! This script changes the group policy settings of the virtual machine, potentially disabling key features of Windows that are required for the forensics question. If, after two hours, you still can't solve a question, run the script and hope you can solve it afterwards.
If you see big, red errors when the script either tries to set up the firewall or disable services, that is OK. Don't panic.
Sometimes, when the script says that it is providing a list of users/services/programs, the printed list doesn't buffer the first time. In this case, do the following:
Press some random characters like 'jcshbdn' or "45", because I doubt there are users/programs by that name. You'll get an error message; that is OK.
Now you should see a printed list, and can compare it to the README of the VM to see what to add/delete.

Note that this script can't update apps like Firefox and Notepad++; that you'll need to do yourself. Other than that, it should make your life easier!
