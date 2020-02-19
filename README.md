# Awesome Windows Red Team [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A curated list of awesome Windows talks, tools and resources for Red Teams, from beginners to ninjas.

## Contents

* [Books](#books)
* [Courses](#courses)
* [System Architecture](#system-architecture)
  * [Active Directory](#active-directory)
  * [Kerberos](#kerberos)
  * [Lssass SAM NTLM GPO](#lssass-sam-ntlm-gpo)
  * [WinAPI](#winapi)
* [Lateral Movement](#lateral-movement)
  * [Pass the Hash](#pass-the-hash)
  * [Pass the Ticket](#pass-the-ticket)
  * [LLMNR/NBT-NS poisoning](#llmnr-nbtns-poisoning)
* [Privilege Escalation](#privilege-escalation)
  * [UAC bypass](#uac-bypass)
  * [Token Impersonation](#token-impersonation)
* [Defense Evasion](#defense-evasion)
  * [AV evasion](#av)
  * [AMSI](#amsi)
* [Exfiltration](#exfiltration)
* [PowerShell](#powershell)
* [Phishing](#phishing)
  * [Maldocs](#maldocs)
  * [Macros](#macros)
  * [DDE](#dde)
  * [HTA](#hta)
* [Tools](#tools)

## Books

* [Windows Internals, Seventh Edition, Part 1](https://www.amazon.com.br/Windows-Internals-Book-User-Mode/dp/0735684189?tag=goog0ef-20&smid=A1ZZFT5FULY4LN)
* [Windows Internals, Sixth Edition, Part 1](https://www.amazon.com.br/Windows-Internals-Part-Developer-Reference-ebook/dp/B00JDMPHIG?tag=goog0ef-20&smid=A18CNA8NWQSYHH)
* [Windows Internals, Sixth Edition, Part 2](https://www.amazon.com/Windows-Internals-Part-Developer-Reference/dp/0735665877)
* [How to Hack Like a PORNSTAR: A step by step process for breaking into a BANK](https://www.amazon.com/How-Hack-Like-PORNSTAR-breaking-ebook/dp/B01MTDLGQQ)
* [Windows® via C/C++ (Developer Reference) (English Edition)](https://www.amazon.com.br/Windows%C2%AE-via-Developer-Reference-English-ebook/dp/B00JDMQK9G/ref=sr_1_1?__mk_pt_BR=%C3%85M%C3%85%C5%BD%C3%95%C3%91&keywords=Windows%C2%AE+via+C%2FC%2B%2B+%28Developer+Reference%29+%28English+Edition%29&qid=1582123720&s=digital-text&sr=1-1)
* [The Hacker Playbook 3: Practical Guide To Penetration Testing](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B07CSPFYZ2)

## Courses

* [Professor Messer's CompTIA SY0-501 Security+ Course](http://www.professormesser.com/security-plus/sy0-501/sy0-501-training-course/)
* [Penetration Testing with Kali (PWK) Online Security Training Course](https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/)
* [Offensive Security Certified Expert](https://www.offensive-security.com/information-security-certifications/osce-offensive-security-certified-expert/)
* [Advanced Windows Exploitation: Live Hands-on Penetration Testing Training](https://www.offensive-security.com/information-security-training/advanced-windows-exploitation/)
* [Windows API Exploitation Recipes: Processes, Tokens and Memory RW](https://www.pentesteracademy.com/course?id=31)
* [Powershell for Pentesters - Pentester Academy](https://www.pentesteracademy.com/course?id=21)
* [WMI Attacks and Defense - Pentester Academy](https://www.pentesteracademy.com/course?id=34)
* [Windows Red Team Lab - Pentester Academy](https://www.pentesteracademy.com/redteamlab)

## System Architecture

### Active Directory

* [ADsecurity.org](https://adsecurity.org/)
* [DerbyCon4 - How to Secure and Sys Admin Windows like a Boss](https://www.youtube.com/watch?v=jKpaaDKVovk&t=0s&list=PLz8yKJBzAxrslURpq0TcmLl7JS-sRNmog&index=79)
* [DEFCON 20: Owned in 60 Seconds: From Network Guest to Windows Domain Admin](https://www.youtube.com/watch?v=nHU3ujyw_sQ)
* [BH2015 - Red Vs. Blue: Modern Active Directory Attacks, Detection, And Protection](https://www.youtube.com/watch?v=b6GUXerE9Ac)
* [BH2016 - Beyond the Mcse: Active Directory for the Security Professional](https://www.youtube.com/watch?v=2w1cesS7pGY)
* [BH2017 - Evading Microsoft ATA for Active Directory Domination ](https://www.youtube.com/watch?v=bHkv63-1GBY)
* [DEFCON 26 - Exploiting Active Directory Administrator Insecurities](https://www.youtube.com/watch?v=WaGgofGnWaI)
* [BH2017 - An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.youtube.com/watch?v=ys1LZ1MzIxE)
* [DerbyCon7 - Building the DeathStar getting Domain Admin with a push of a button (aka how I almost automated myself out pf a job)](https://www.youtube.com/watch?v=kGoc_apljpU)
* [DerbyCon4 - Abusing Active Directory in Post Exploitation](https://www.youtube.com/watch?v=sTU-70dD-Ok&t=0s&list=PLz8yKJBzAxrslURpq0TcmLl7JS-sRNmog&index=12)


### Kerberos

* [Kerberos (I): How does Kerberos work? – Theory](https://www.tarlogic.com/en/blog/how-kerberos-works/?amp&__twitter_impression=true)
* [Protecting Privileged Domain Accounts: Network Authentication In-Depth](https://digital-forensics.sans.org/blog/2012/09/18/protecting-privileged-domain-accounts-network-authentication-in-depth)
* [Basic attacks on communication protocols – replay and reflection attacks](https://steemit.com/education/@edwardthomson/basic-attacks-on-communication-protocols-replay-and-reflection-attacks)
* [MicroNugget: How Does Kerberos Work?](https://www.youtube.com/watch?v=kp5d8Yv3-0c) 
* [MIT 6.858 Fall 2014 Lecture 13: Kerberos](https://www.youtube.com/watch?v=bcWxLl8x33c)
* [DerbyCon4 - Et tu Kerberos](https://www.youtube.com/watch?v=RIRQQCM4wz8&t=0s&list=PLz8yKJBzAxrslURpq0TcmLl7JS-sRNmog&index=14)
* [DerbyCon7 - Return From The Underworld The Future Of Red Team Kerberos](https://www.youtube.com/watch?v=E_BNhuGmJwM&t=0s&index=2&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
* [BH2014 - Abusing Microsoft Kerberos: Sorry You Guys Don't Get It](https://www.youtube.com/watch?v=lJQn06QLwEw)
* [DerbyCon4 - Attacking Microsoft Kerberos Kicking the Guard Dog of Hades](https://www.youtube.com/watch?v=PUyhlN-E5MU&t=0s&list=PLz8yKJBzAxrslURpq0TcmLl7JS-sRNmog&index=57)
* [Kerberos in the Crosshairs: Golden Tickets, Silver Tickets, MITM, and More](https://digital-forensics.sans.org/blog/2014/11/24/kerberos-in-the-crosshairs-golden-tickets-silver-tickets-mitm-more)
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)

### Lsass SAM NTLM GPO

* [Retrieving NTLM Hashes without touching LSASS: the “Internal Monologue” Attack](https://www.andreafortuna.org/dfir/retrieving-ntlm-hashes-without-touching-lsass-the-internal-monologue-attack/)
* [ATT&CK - Credential Dumping](https://attack.mitre.org/wiki/Technique/T1003)
* [BH2002 - Cracking NTLMv2 Authentication](https://www.youtube.com/watch?v=x4c8J70kHKc)
* [DerbyCon7 - Securing Windows with Group Policy ](https://www.youtube.com/watch?v=Upeaa2rgozk&t=0s&index=66&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
* [Abusing GPO Permissions](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [Targeted Kerberoasting](https://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/)

### WinAPI

* [DerbyCon4 - Getting Windows to Play with Itself: A Pen Testers Guide to Windows API Abuse](https://www.youtube.com/watch?v=xll_RXQX_Is&index=7&list=PLNhlcxQZJSm8o9c_2_iDDTV6tCPdMp5dg&t=0s)

## Lateral Movement

### Pass the Hash

* [ATT&CK - Pass the Hash](https://attack.mitre.org/wiki/Technique/T1075)
* [BH2013 - Pass the Hash and other credential theft and reuse: Preventing Lateral Movement...](https://www.youtube.com/watch?v=xxwIh2pvbyw&t=345s)
* [BH2013 - Pass the Hash 2: The Admin's Revenge](https://www.youtube.com/watch?v=A5xntvKaRlk)
* [From Pass-the-Hash to Pass-the-Ticket with No Pain](https://resources.infosecinstitute.com/pass-hash-pass-ticket-no-pain/#gref)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)

### Pass the Ticket

* [ATT&CK - Pass the Ticket](https://attack.mitre.org/wiki/Technique/T1097)

### LLMNR/NBT-NS poisoning

* [An SMB Relay Race – How To Exploit LLMNR and SMB Message Signing for Fun and Profit](https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/)

## Privilege Escalation

* [Level Up! Practical Windows Privilege Escalation - Andrew Smith](https://www.youtube.com/watch?v=PC_iMqiuIRQ)
* [Windows Privilege Escalation Presentation](https://www.youtube.com/watch?v=mcJ3aRSqGSo)
* [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)
* [DEF CON 22 - Kallenberg and Kovah - Extreme Privilege Escalation On Windows 8/UEFI Systems](https://www.youtube.com/watch?v=d6VCri6sPnY)
* [DEF CON 25 - Morten Schenk - Taking Windows 10 Kernel Exploitation to the next level](https://www.youtube.com/watch?v=Gu_5kkErQ6Y)
* [DerbyCon7 - Not a Security Boundary Bypassing User Account Control](https://www.youtube.com/watch?v=c8LgqtATAnE&t=0s&index=21&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)

### Token Impersonation

* [Fun with Incógnito](HTTPS://offensive-security.com/metasploit-unleashed/fun-incognito/)
* [Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

## Defense Evasion

### AV

* [DerbyCon3 - Antivirus Evasion Lessons Learned](https://www.youtube.com/watch?v=ycgaekqAkpA)
* [DerbyCon7 - T110 Modern Evasion Techniques](https://www.youtube.com/watch?v=xcA2riLyHtQ)
* [DerbyCon7 - Evading Autoruns](https://www.youtube.com/watch?v=AEmuhCwFL5I)
* [Red Team Techniques for Evading, Bypassing & Disabling MS](https://www.youtube.com/watch?v=2HNuzUuVyv0)
* [How to Bypass Anti-Virus to Run Mimikatz](https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/)
* [AV Evasion - Obfuscating Mimikatz](https://www.youtube.com/watch?v=9pwMCHlNma4)
* [Getting PowerShell Empire Past Windows Defender](https://www.blackhillsinfosec.com/getting-powershell-empire-past-windows-defender/)

### AMSI
* [Windows Defender ATP machine learning and AMSI: Unearthing script-based attacks that ‘live off the land’ ](https://www.microsoft.com/security/blog/2017/12/04/windows-defender-atp-machine-learning-and-amsi-unearthing-script-based-attacks-that-live-off-the-land/)
* [Antimalware Scan Interface (AMSI) — A Red Team Analysis on Evasion] (https://iwantmore.pizza/posts/amsi.html)

### LAPS

* [Local Administrator Password Solution](https://docs.microsoft.com/en-us/previous-versions/mt227395(v=msdn.10))
* [Malicious use of Microsoft LAPS](https://akijosberryblog.wordpress.com/2019/01/01/malicious-use-of-microsoft-laps/)

### AppLocker & Application Whitelisting

* [What Is AppLocker?](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)
* [How to Evade Application Whitelisting Using REGSVR32](https://www.blackhillsinfosec.com/evade-application-whitelisting-using-regsvr32/)
* [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)

## Exfiltration

* [Abusing Windows Management Instrumentation (WMI)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
* [DEF CON 23 - Panel - WhyMI so Sexy: WMI Attacks - Real Time Defense and Advanced Forensics](https://www.youtube.com/watch?v=xBd6p-Lz3kE)
* [DerbyCon3 - Living Off The Land A Minimalist's Guide To Windows Post Exploitation](https://www.youtube.com/watch?v=j-r6UonEkUw)

## PowerShell

* [DEF CON 18 - David Kennedy "ReL1K" & Josh Kelley - Powershell...omfg](https://www.youtube.com/watch?v=q5pA49C7QJg)
* [DEF CON 22 - Investigating PowerShell Attacks](https://www.youtube.com/watch?v=EcOf1s90vsg)
* [DerbyCon2016 - 106 PowerShell Secrets and Tactics Ben0xA](https://www.youtube.com/watch?v=mPPv6_adTyg)
* [Daniel Bohannon – Invoke-Obfuscation: PowerShell obFUsk8tion](https://www.youtube.com/watch?v=uE8IAxM_BhE)
* [BH2017 - Revoke-Obfuscation: PowerShell Obfuscation Detection (And Evasion) Using Science](https://www.youtube.com/watch?v=x97ejtv56xw)

## Phishing

### Maldocs

* [Phishing with Maldocs](https://www.n00py.io/2017/04/phishing-with-maldocs/)
* [Phishing with Empire](https://enigma0x3.net/2016/03/15/phishing-with-empire/)

### Macros

* [Phishing with Macros and Powershell](https://www.securitysift.com/phishing-with-macros-and-powershell/)

### DDE

* [About Dynamic Data Exchange](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/about-dynamic-data-exchange)
* [Abusing Microsoft Office DDE](https://www.securitysift.com/abusing-microsoft-office-dde/)
* [Microsoft Office Dynamic Data Exchange(DDE) attacks](https://resources.infosecinstitute.com/microsoft-office-dynamic-data-exchangedde-attacks/#gref)
* [Office-DDE-Payloads](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)

### HTA

* [Hacking around HTA files](http://blog.sevagas.com/?Hacking-around-HTA-files)

## Tools
 
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [BloodHound](https://github.com/BloodHoundAD/BloodHound)
* [Empire](https://github.com/EmpireProject/Empire)
* [Nishang](https://github.com/samratashok/nishang)
* [Responder](https://github.com/SpiderLabs/Responder)
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
* [PSExec](https://www.toshellandback.com/2017/02/11/psexec/)

### Adversary Emulation
* [Cobalt Strike](https://www.cobaltstrike.com/)
* [Red Team Automation - RTA](https://github.com/endgameinc/RTA)
* [CALDERA](https://github.com/mitre/caldera)
* [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
* [Metta](https://github.com/uber-common/metta)

# Other Awesome Lists & sources

* [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)
* [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)
* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
* [Awesome Pentest](https://github.com/Muhammd/Awesome-Pentest)
* [Red Teaming Experiments](https://ired.team/)

# Contributing
Your contributions are always welcome! Please take a look at the contribution guidelines first.

If you have any question about this opinionated list, do not hesitate to contact me @\_mvalle\_ on Twitter or open an issue on GitHub.
