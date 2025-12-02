# OSEP Hazırlıq Roadmap-i: 0-dan Master Səviyyəyə

## 📋 Ümumi Məlumat

**Ümumi müddət:** 6-8 ay (hər gün 3-4 saat intensive)  
**Metodologiya:** Hər mövzunu 3 dəfə keçin - Nəzəriyyə → Praktika → Öz implementasiyası  
**Qayda:** Növbəti mövzuya keçməzdən əvvəl cari mövzunu mükəmməl bilməlisiniz

---

## FAZA 1: TƏMƏLLƏRİN MÖHKƏM QURULMASI (8-10 həftə)

### Həftə 1-2: Programming Fundamentals Enhancement

**C# Programming (14 gün)**
- ✅ C# Syntax və OOP Concepts (3 gün)
  - Classes, Objects, Inheritance, Polymorphism
  - Delegates, Events, LINQ
  - File I/O və Exception Handling
- ✅ .NET Framework Architecture (2 gün)
  - CLR, CTS, CLS anlayışları
  - Assembly structure və GAC
  - Managed vs Unmanaged code
- ✅ P/Invoke və Interop (3 gün)
  - Win32 API çağırışları
  - DllImport attributes
  - Marshal class və unsafe code
- ✅ Reflection və Dynamic Code (3 gün)
  - Assembly.Load metodları
  - Type manipulation
  - Dynamic method invocation
- ✅ Praktiki Layihələr (3 gün)
  - Simple shellcode runner yazın (C#)
  - Process enumeration tool
  - Registry modifier

**Resurslar:**
- Udemy: "C# Advanced Topics: Prepare for Technical Interviews"
- Microsoft Learn: C# Documentation
- "C# 10.0 in a Nutshell" kitabı

**PowerShell Deep Dive (7 gün)**
- ✅ Advanced PowerShell (3 gün)
  - .NET integration PowerShell-də
  - Runspaces və Pipeline
  - PSCustomObject və Hashtables
- ✅ PowerShell Internals (2 gün)
  - CLM (Constrained Language Mode)
  - Execution Policy bypass
  - Script Block Logging
- ✅ Offensive PowerShell (2 gün)
  - Invoke-Expression alternatives
  - Download cradles
  - In-memory execution

**Resurslar:**
- "PowerShell for Sysadmins" kitabı
- PowerSploit GitHub source code oxuyun

---

### Həftə 3-4: Windows Internals (14 gün)

**Windows Architecture (5 gün)**
- ✅ Process və Thread Structure (2 gün)
  - Process Environment Block (PEB)
  - Thread Environment Block (TEB)
  - Process Injection points
- ✅ Memory Management (2 gün)
  - Virtual Memory layout
  - Heap vs Stack
  - Memory protection (DEP, ASLR)
- ✅ Windows API Deep Dive (1 gün)
  - Kernel32.dll, ntdll.dll functions
  - Native API vs Win32 API

**Authentication Mechanisms (4 gün)**
- ✅ LSASS və Credential Storage (2 gün)
  - LSA Secrets
  - Cached credentials
  - Credential Guard
- ✅ Kerberos Protocol (2 gün)
  - AS-REQ, AS-REP, TGS-REQ, TGS-REP
  - Ticket structure (PAC, SID)
  - Delegation types

**Registry və Persistence (2 gün)**
- Registry hives structure
- Autorun locations
- COM hijacking concepts

**Lab məşqləri (3 gün)**
- WinDbg ilə process debug
- Mimikatz source code oxuyun
- Öz credential dumper-inizi yazın (C#)

**Resurslar:**
- "Windows Internals Part 1 & 2" (Mark Russinovich)
- Pavel Yosifovich YouTube channel
- Sysinternals tools documentation

---

### Həftə 5-6: Active Directory Fundamentals (14 gün)

**AD Architecture (5 gün)**
- ✅ Domain Structure (2 gün)
  - DC, Domain, Forest, Tree
  - Trust relationships
  - Schema və Global Catalog
- ✅ Group Policy Objects (1 gün)
  - GPO processing order
  - SYSVOL və NETLOGON shares
- ✅ LDAP və DNS (2 gün)
  - LDAP queries structure
  - DNS SRV records
  - AD-Integrated DNS

**AD Authentication (4 gün)**
- ✅ NTLM Authentication Flow (2 gün)
  - Challenge-Response mechanism
  - Net-NTLMv1 vs Net-NTLMv2
  - SMB Relay attacks theory
- ✅ Kerberos in AD (2 gün)
  - KDC role
  - Service Principal Names (SPNs)
  - Kerberoasting theory

**AD Permissions (3 gün)**
- ✅ ACLs və ACEs (1 gün)
- ✅ Delegation (1 gün)
  - Unconstrained Delegation
  - Constrained Delegation
  - Resource-Based Constrained Delegation
- ✅ Dangerous Permissions (1 gün)
  - GenericAll, WriteDACL, WriteOwner
  - DCSync rights

**Lab Setup (2 gün)**
- Öz AD lab-ınızı qurun (2-3 DC, 5+ users/computers)
- Vulnerable configurations yaradın
- Enumeration script-ləri yazın

**Resurslar:**
- "Active Directory" (Laura E. Hunter)
- Microsoft AD Documentation
- Harmj0y blog (SpecterOps)

---

### Həftə 7-8: Assembly və Memory Concepts (14 gün)

**Assembly Reading (6 gün)**
- ✅ x86/x64 Architecture (2 gün)
  - Registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP)
  - Calling conventions (fastcall, stdcall)
  - Stack frames
- ✅ Common Instructions (2 gün)
  - MOV, LEA, PUSH, POP, CALL, JMP
  - Arithmetic və Logic operations
  - Conditional jumps
- ✅ Debugger Usage (2 gün)
  - x64dbg basics
  - WinDbg basics
  - IDA Free

**Shellcode Fundamentals (4 gün)**
- ✅ Shellcode Structure (2 gün)
  - Position Independent Code (PIC)
  - API resolution (PEB walking)
  - Null byte avoidance
- ✅ Shellcode Encoding (2 gün)
  - XOR encoding
  - Alphanumeric encoding
  - Polymorphic shellcode

**Buffer Overflow Basics (4 gün)**
- ✅ Stack-based Buffer Overflow (2 gün)
  - EIP control
  - Bad characters
  - JMP ESP technique
- ✅ DEP və ASLR Bypass Theory (2 gün)
  - ROP chains konsepti
  - Gadget search

**Resurslar:**
- "Practical Malware Analysis" (Michael Sikorski)
- OpenSecurityTraining2
- OSCP Buffer Overflow section

---

### Həftə 9-10: Networking & Protocols Deep Dive (14 gün)

**Protocol Analysis (7 gün)**
- ✅ TCP/IP Stack (2 gün)
  - Three-way handshake
  - TCP flags və states
  - Window size və congestion
- ✅ HTTP/HTTPS Deep Dive (2 gün)
  - Request/Response structure
  - Headers və Methods
  - TLS handshake
- ✅ SMB Protocol (2 gün)
  - SMBv1 vs SMBv2/3
  - Named pipes
  - IPC$ share
- ✅ DNS, LDAP, Kerberos Packets (1 gün)

**Packet Analysis (4 gün)**
- Wireshark filters mastery
- Burp Suite advanced usage
- Network forensics

**Pivoting Concepts (3 gün)**
- Port forwarding theory
- SOCKS proxies
- Tunneling (SSH, DNS, HTTP)

**Resurslar:**
- "TCP/IP Illustrated" (W. Richard Stevens)
- Wireshark documentation
- Chris Greer YouTube (Packet Analysis)

---

## FAZA 2: OSEP-SPESİFİK TƏLİM (12-14 həftə)

### Həftə 11-13: Client-Side Attacks (21 gün)

**VBA Macros (7 gün)**
- ✅ VBA Basics və IDE (1 gün)
- ✅ AutoOpen və Document_Open (1 gün)
- ✅ Win32 API from VBA (2 gün)
  - VirtualAlloc, CreateThread
  - Shellcode execution
- ✅ Obfuscation Techniques (2 gün)
  - Variable name randomization
  - String concatenation
  - VBA stomping
- ✅ HTML Smuggling (1 gün)

**JScript/VBScript (7 gün)**
- ✅ WSH Execution (1 gün)
- ✅ DotNetToJScript (2 gün)
  - C# to JScript conversion
  - In-memory execution
- ✅ SharpShooter (2 gün)
- ✅ Payload delivery methods (2 gün)
  - .hta files
  - .xsl transforms
  - .chm files

**Phishing Infrastructure (7 gün)**
- ✅ GoPhish setup (1 gün)
- ✅ Email spoofing və DMARC bypass (2 gün)
- ✅ Payload hosting (2 gün)
- ✅ Social engineering techniques (2 gün)

**Lab məşqləri:**
- 10+ macro variant yazın (hər biri fərqli bypass)
- JScript shellcode runner chain
- Tam phishing campaign simulate edin

---

### Həftə 14-16: AV/EDR Evasion Fundamentals (21 gün)

**Antivirus Evasion (10 gün)**
- ✅ AV Detection Methods (2 gün)
  - Signature-based
  - Heuristic analysis
  - Behavioral detection
  - Machine learning models
- ✅ Static Evasion (3 gün)
  - Payload encoding (XOR, AES)
  - String obfuscation
  - API hashing
  - Sleep timers
- ✅ Dynamic Evasion (3 gün)
  - Sandbox detection
  - Non-emulated APIs
  - Time-based checks
  - User interaction checks
- ✅ C# Evasion Techniques (2 gün)
  - Custom crypters
  - Reflective loading

**AMSI Bypass (5 gün)**
- ✅ AMSI Architecture (2 gün)
  - AmsiScanBuffer flow
  - Context initialization
- ✅ Memory Patching (2 gün)
  - Assembly-level patching
  - PowerShell AMSI bypass
- ✅ Reflection Bypass (1 gün)

**ETW Bypass (3 gün)**
- Event Tracing structure
- ETW patching

**PowerShell CLM Bypass (3 gün)**
- Runspace manipulation
- AppDomain creation
- InstallUtil technique

**Lab məşqləri:**
- Defender bypass payload (5+ method)
- AMSI bypass implement edin (3+ variant)
- CLM bypass chain

---

### Həftə 17-19: Process Injection & Migration (21 gün)

**Classic Injection (7 gün)**
- ✅ Process Injection Theory (2 gün)
  - VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- ✅ C# Implementation (3 gün)
  - Process selection logic
  - Error handling
  - PPID spoofing
- ✅ PowerShell Implementation (2 gün)

**DLL Injection (7 gün)**
- ✅ Standard DLL Injection (2 gün)
- ✅ Reflective DLL Injection (3 gün)
  - PE parsing
  - Manual mapping
  - Invoke-ReflectivePEInjection
- ✅ DLL Proxying (2 gün)

**Advanced Techniques (7 gün)**
- ✅ Process Hollowing (3 gün)
  - NtUnmapViewOfSection
  - Full implementation C#-də
- ✅ APC Injection (2 gün)
- ✅ Process Doppelgänging (2 gün)

**Lab məşqləri:**
- Hər injection type-ı implement edin
- EDR evasion-la combine edin
- Shellcode runner tool kit

---

### Həftə 20-21: AppLocker & Whitelisting Bypass (14 gün)

**AppLocker Deep Dive (7 gün)**
- ✅ AppLocker Rules (2 gün)
  - Publisher, Path, Hash rules
  - Default rule sets
- ✅ Trusted Folders Abuse (2 gün)
- ✅ LOLBins (2 gün)
  - regsvr32, rundll32, mshta
  - InstallUtil, MSBuild
- ✅ DLL Execution Bypass (1 gün)

**Advanced Bypass (7 gün)**
- ✅ Alternate Data Streams (2 gün)
- ✅ Custom Runspace in CLM (3 gün)
- ✅ C# InstallUtil technique (2 gün)

**Lab məşqləri:**
- AppLocker lab setup (strict rules)
- 10+ bypass method test edin

---

### Həftə 22-24: Network Filtering Bypass (21 gün)

**Web Proxy Bypass (7 gün)**
- ✅ Proxy detection və configuration (2 gün)
- ✅ Proxy-aware C2 (3 gün)
- ✅ User-Agent manipulation (2 gün)

**DNS Tunneling (7 gün)**
- ✅ dnscat2 deep dive (3 gün)
- ✅ Custom DNS tunneling (4 gün)
  - Python implementation
  - C# DNS queries

**Domain Fronting (7 gün)**
- ✅ CDN-based fronting (3 gün)
  - Azure CDN setup
  - Cloudflare workers
- ✅ Meterpreter integration (2 gün)
- ✅ Custom fronted C2 (2 gün)

---

## FAZA 3: ACTIVE DIRECTORY EXPLOITATION (8-10 həftə)

### Həftə 25-27: AD Enumeration & Initial Access (21 gün)

**AD Enumeration Tools (7 gün)**
- ✅ PowerView Deep Dive (3 gün)
  - All cmdlets mastery
  - Custom filters
  - Source code oxuyun
- ✅ BloodHound Mastery (2 gün)
  - Custom queries
  - SharpHound collectors
  - Python bloodhound.py
- ✅ ADRecon, PingCastle (2 gün)

**Manual Enumeration (7 gün)**
- ✅ LDAP Queries (3 gün)
  - Raw LDAP filters
  - C# DirectorySearcher
  - PowerShell [ADSISearcher]
- ✅ RPC Enumeration (2 gün)
- ✅ SMB Enumeration (2 gün)

**Credential Access (7 gün)**
- ✅ LLMNR/NBT-NS Poisoning (2 gün)
  - Responder
  - Inveigh
- ✅ SMB Relay Attacks (2 gün)
- ✅ IPv6 DNS Takeover (1 gün)
- ✅ Password Spraying (2 gün)

---

### Həftə 28-30: Lateral Movement (21 gün)

**Windows Lateral Movement (10 gün)**
- ✅ WMI Execution (2 gün)
  - wmic usage
  - C# WMI calls
- ✅ PSRemoting (2 gün)
  - Enter-PSSession
  - Invoke-Command
  - Delegation issues
- ✅ PsExec Variants (2 gün)
  - SysInternals PsExec
  - Impacket psexec.py
  - Custom implementation
- ✅ DCOM Exploitation (2 gün)
- ✅ Scheduled Tasks (2 gün)

**Linux Lateral Movement (5 gün)**
- ✅ SSH Keys (2 gün)
  - Key theft
  - SSH-Agent hijacking
  - ControlMaster abuse
- ✅ Ansible Exploitation (3 gün)
  - Playbook abuse
  - Vault passwords

**RDP Techniques (6 gün)**
- ✅ RDP Pass-the-Hash (2 gün)
- ✅ RDP Hijacking (2 gün)
- ✅ Chisel SOCKS pivot (2 gün)

---

### Həftə 31-32: Privilege Escalation (14 gün)

**Windows PrivEsc (7 gün)**
- ✅ Token Manipulation (2 gün)
  - SeImpersonatePrivilege
  - Potato attacks (all variants)
- ✅ Service Exploitation (2 gün)
  - Unquoted service paths
  - Weak permissions
- ✅ Registry Autoruns (1 gün)
- ✅ DLL Hijacking (2 gün)

**Linux PrivEsc (7 gün)**
- ✅ SUID/SGID binaries (2 gün)
- ✅ Sudo misconfigurations (2 gün)
- ✅ Cron jobs (1 gün)
- ✅ Shared libraries (2 gün)

---

### Həftə 33-34: Advanced AD Attacks (14 gün)

**Kerberos Attacks (7 gün)**
- ✅ Kerberoasting (2 gün)
  - Rubeus usage
  - Custom implementation
- ✅ AS-REP Roasting (1 gün)
- ✅ Golden Ticket (2 gün)
- ✅ Silver Ticket (2 gün)

**Delegation Abuse (7 gün)**
- ✅ Unconstrained Delegation (2 gün)
  - Printer Bug
  - SpoolSample
- ✅ Constrained Delegation (3 gün)
  - S4U2Self və S4U2Proxy
  - Protocol transition
- ✅ Resource-Based Constrained Delegation (2 gün)

---

### Həftə 35-36: Forest/Domain Trusts (14 gün)

**Trust Types (5 gün)**
- ✅ Parent-Child Trusts (2 gün)
- ✅ External Trusts (2 gün)
- ✅ Forest Trusts (1 gün)

**Trust Attacks (9 gün)**
- ✅ SID History Injection (3 gün)
- ✅ Golden Ticket cross-forest (3 gün)
- ✅ Printer Bug for unconstrained (3 gün)

---

## FAZA 4: SQL ATTACKS & SPECIAL TOPICS (3-4 həftə)

### Həftə 37-38: MSSQL Attacks (14 gün)

**MSSQL Enumeration (4 gün)**
- ✅ SQL Server discovery (1 gün)
- ✅ PowerUpSQL (2 gün)
- ✅ Manual enumeration (1 gün)

**MSSQL Exploitation (10 gün)**
- ✅ xp_cmdshell (2 gün)
- ✅ Custom assemblies (3 gün)
- ✅ UNC Path injection (2 gün)
- ✅ Linked SQL servers (3 gün)
  - OPENQUERY abuse
  - Chain exploitation

---

### Həftə 39-40: Linux Post-Exploitation & Kiosk Breakout (14 gün)

**Linux Persistence (7 gün)**
- ✅ .bashrc, .vimrc backdoors (2 gün)
- ✅ Shared library hijacking (3 gün)
  - LD_PRELOAD
  - LD_LIBRARY_PATH
- ✅ Cron job backdoors (2 gün)

**Kiosk Breakout (7 gün)**
- ✅ Browser escape techniques (3 gün)
- ✅ Firefox profile abuse (2 gün)
- ✅ Linux kiosk escape (2 gün)

---

## FAZA 5: PEN-300 COURSE & LAB (8-12 həftə)

### Həftə 41-48: PEN-300 Material

**Course Study (4 həftə)**
- PDF-i 3 dəfə oxuyun (hər dəfə fərqli notlar)
- Video-ları 1.5x speed-də izləyin
- Hər module-dan sonra "Extra Mile" challenges

**Lab Practice (4 həftə)**
- Bütün lab maşınlarını compromise edin
- Challenge lab-ları 2 dəfə edin (bir dəfə notes ilə, bir dəfə yox)
- Öz methodology template-inizi yaradın

---

## FAZA 6: EXAM HAZİRLIĞI (4 həftə)

### Həftə 49-50: HTB Offshore Pro Labs (14 gün)

### Həftə 51-52: Mock Exams & Final Review (14 gün)
- Proving Grounds (10+ OSEP-level boxes)
- Cyberseclabs
- Cheat sheet finalize
- Report template hazırlayın

---

## 🛠️ ƏSAS ALƏTLƏR SİYAHISI

**Development:**
- Visual Studio 2022
- VSCode + C# extension
- .NET Framework 4.8

**AD Tools:**
- PowerView, SharpView
- BloodHound + SharpHound
- Rubeus, Certify
- Impacket suite
- CrackMapExec

**Evasion:**
- ConfuserEx, Obfuscar
- DotNetToJScript
- SharpShooter

**C2 Frameworks:**
- Metasploit
- Covenant
- Sliver (optional)

**Pivoting:**
- Chisel
- ligolo-ng
- sshuttle

---

## 📚 ƏSAS RESURSLLAR

**Kitablar:**
1. "Windows Internals" (Part 1 & 2)
2. "Active Directory Security" (Sean Metcalf)
3. "Practical Malware Analysis"
4. "Black Hat C#"
5. "PowerShell for Sysadmins"

**Bloqlar:**
- harmj0y.net
- SpecterOps blog
- Red Team Notes
- ired.team
- S3cur3Th1sSh1t blog

**YouTube:**
- John Hammond
- IppSec
- HackerSploit
- 13Cubed

**GitHub:**
- BC-SECURITY (Empire, Covenant)
- GhostPack tools (Rubeus, Seatbelt, etc)
- PowerShellMafia

---

## ✅ HƏR FAZADAN SONRA ÖZÜNÜZƏKSİYA

**Faza 1 sonra:**
- C#-da shellcode runner yaza bilirsinizmi?
- Process injection implement edə bilirsinizmi?
- AD-ni manual enumerate edə bilirsinizmi?

**Faza 2 sonra:**
- AV bypass payload yaza bilirsinizmi?
- AMSI bypass implement edə bilirsinizmi?
- VBA macro dropper yaza bilirsinizmi?

**Faza 3 sonra:**
- AD-də lateral movement edə bilirsinizmi?
- Kerberos attacks başa düşürsünüzmü?
- Trust relationship exploit edə bilirsinizmi?

**Faza 5 sonra:**
- PEN-300 lab-ları bitirdinizsə EXAM-a hazırsınız

---

## 🎯 UĞUR ÜÇÜN QAYDALLAR

1. **Tələsməyin** - Hər konsepti tam başa düşün
2. **Kod yazın** - Hər tool-u özünüz implement edin
3. **Notes aparın** - CherryTree, Obsidian, OneNote
4. **Lab qurun** - Öz lab-ınızda test edin
5. **Break götürün** - Burnout-dan çəkinin
6. **Community** - Discord, Reddit-də aktiv olun

---

## 📅 EXAM GÜNÜNƏXEKLİST

- [ ] VPN test
- [ ] Methodology checklist hazır
- [ ] Screenshot tool
- [ ] Report template
- [ ] Snacks və su
- [ ] 48 saat plan
