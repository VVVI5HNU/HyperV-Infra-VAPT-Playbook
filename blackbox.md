# Hyper-V / Windows Infrastructure VAPT Playbook — Black Box

> **Legal Notice:** This playbook is for use only when written authorization has been obtained from the asset owner. Unauthorized use is illegal. All testing must stay within defined scope.

## Scope
Use when only IP addresses / hostnames are provided. No credentials.

## Objective
Identify exposed services, weak configurations, outdated components, authentication weaknesses, misconfigurations, and attack paths across Windows Server and Hyper-V infrastructure.

## Tools Required
- nmap, crackmapexec / netexec, smbclient, smbmap, enum4linux-ng
- ldapsearch, rpcclient, impacket suite (rpcdump.py, GetNPUsers.py, lookupsid.py)
- kerbrute, dig, snmpwalk, onesixtyone, nbtscan
- testssl.sh, nikto, gobuster / ffuf, eyewitness / gowitness
- Nessus / OpenVAS (automated baseline)
- Responder (passive/listen mode only for LLMNR detection)
- curl, whatweb

---

# Phase 1 — Recon & Enumeration

## 1.1 Host Discovery

```bash
# ICMP sweep
ping -c 4 <IP>
nmap -sn <CIDR>

# ARP-based (if on same subnet)
nmap -sn -PR <CIDR>

# TCP SYN probe when ICMP is blocked
nmap -sn -PS22,80,443,445,3389 <CIDR>
```

**Vulnerable Signs**
- Undocumented live hosts in scope
- Hosts responding that are outside expected inventory

---

## 1.2 OS Fingerprinting

```bash
nmap -O --osscan-guess <IP>
nmap -A -T3 <IP>
```

**Vulnerable Signs**
- End-of-life OS versions (Windows Server 2008, 2003, 2000)
- Mixed OS versions suggesting unpatched legacy hosts

---

## 1.3 Full TCP Port Scan

```bash
nmap -Pn -p- -sS -T3 --min-rate 1000 -oN tcp_fullscan.txt <IP>
```

**Key Ports to Look For**

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80/443/8443/8080 | HTTP/HTTPS |
| 88 | Kerberos |
| 111 | RPC |
| 135 | MSRPC |
| 137-139 | NetBIOS |
| 389/636 | LDAP/LDAPS |
| 445 | SMB |
| 464 | Kerberos passwd change |
| 593 | RPC over HTTP |
| 636 | LDAPS |
| 1433 | MSSQL |
| 2179 | Hyper-V VM connect |
| 3268/3269 | Global Catalog |
| 3389 | RDP |
| 5985/5986 | WinRM HTTP/HTTPS |
| 6600 | Hyper-V |
| 47001 | WinRM alt |
| 49152-65535 | Dynamic RPC |

**Vulnerable Signs**
- Legacy protocols exposed (FTP, Telnet, SMBv1)
- Management interfaces on all interfaces instead of management VLAN
- Dynamic RPC range fully open externally

---

## 1.4 Full UDP Scan (Critical — Often Missed)

```bash
nmap -sU --top-ports 200 -T3 -oN udp_scan.txt <IP>

# Targeted UDP
nmap -sU -p 53,67,69,123,137,138,161,162,500,4500 <IP>
```

**Vulnerable Signs**
- UDP 161 (SNMP) open
- UDP 137/138 (NetBIOS) open
- UDP 53 open (DNS zone transfer / recursion)
- UDP 123 (NTP) — check for amplification

---

## 1.5 Service & Version Detection

```bash
nmap -sV -sC -p <OPEN_PORTS> <IP> -oN service_scan.txt
```

**Vulnerable Signs**
- Version banners revealing unpatched software
- Admin panels auto-detected
- Default page titles leaking product/version

---

# Phase 2 — NetBIOS / NBT-NS Enumeration

## 2.1 NetBIOS Scan

```bash
nbtscan <CIDR>
nmap --script nbstat -p137 <IP>
```

**Vulnerable Signs**
- Hostname / workgroup name disclosed
- NetBIOS null session possible

---

## 2.2 Comprehensive Windows Enumeration

```bash
enum4linux-ng -A <IP>
```

**Covers:** shares, users, groups, password policy, OS info, RID cycling.

**Vulnerable Signs**
- Users enumerated without credentials
- Weak password policy disclosed
- Domain name / structure leaked

---

# Phase 3 — SMB Testing

## 3.1 SMB Signing Check

```bash
nmap --script smb2-security-mode -p445 <IP>
crackmapexec smb <IP>
# or with netexec (nxc):
nxc smb <IP>
```

**Vulnerable Signs**
- `Message signing enabled but not required`
- `signing: False`

**Risk:** NTLM relay, MITM, lateral movement

---

## 3.2 SMB Protocol Version Check

```bash
nmap --script smb-protocols -p445 <IP>
crackmapexec smb <IP>
```

**Vulnerable Signs**
- `SMBv1: True`
- SMBv2 disabled

**Risk:** EternalBlue, WannaCry, wormable attack surface

---

## 3.3 Anonymous / Null Session SMB Access

```bash
smbclient -L //<IP> -N
smbmap -H <IP> -u null
smbmap -H <IP> -u "" -p ""
crackmapexec smb <IP> -u "" -p "" --shares
```

**Vulnerable Signs**
- Share listing without auth
- Readable shares anonymously (SYSVOL readable without creds is expected; check for others)
- Writable shares (critical — enables SCF/LNK attacks)

---

## 3.4 Legacy SMB Vulnerability Sweep

```bash
nmap --script smb-vuln* -p445 <IP>

# Specific critical checks
nmap --script smb-vuln-ms17-010 -p445 <IP>       # EternalBlue
nmap --script smb-vuln-ms08-067 -p445 <IP>       # MS08-067
nmap --script smb-vuln-cve-2020-0796 -p445 <IP>  # SMBGhost
```

**Vulnerable Signs**
- Any positive NSE vulnerability result
- `VULNERABLE` in output

**Risk:** Remote Code Execution, full system compromise

---

## 3.5 RID Cycling (User Enumeration via SMB)

```bash
# With impacket
lookupsid.py guest@<IP> -no-pass

# With crackmapexec
crackmapexec smb <IP> -u "" -p "" --rid-brute
```

**Vulnerable Signs**
- User accounts enumerated without credentials

---

# Phase 4 — RPC / MSRPC Enumeration

## 4.1 RPC Endpoint Mapper Enumeration

```bash
# Impacket
rpcdump.py <IP>

# rpcclient null session
rpcclient -U "" -N <IP>
  > enumdomusers
  > enumdomgroups
  > querydominfo
  > getdompwinfo
```

**Vulnerable Signs**
- User and group enumeration without credentials
- Password policy disclosed (min length, complexity, lockout threshold)
- Null session accepted by rpcclient

---

## 4.2 WMI / DCOM Exposure

```bash
nmap -p135 --script msrpc-enum <IP>
```

**Vulnerable Signs**
- DCOM interfaces exposed unauthenticated

---

# Phase 5 — Kerberos Enumeration (Port 88)

## 5.1 Kerberos Service Detection

```bash
nmap -p88 -sV <IP>
```

- If port 88 is open, target is likely a Domain Controller.

---

## 5.2 Username Enumeration via Kerberos

```bash
# Kerbrute — no credentials required
kerbrute userenum --dc <IP> -d <DOMAIN> /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

**Vulnerable Signs**
- Valid usernames identified without authentication
- Domain name confirmed

---

## 5.3 AS-REP Roasting (No Pre-auth Accounts)

```bash
# With a list of enumerated usernames
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -no-pass -dc-ip <IP>

# Without username list (tries common names)
GetNPUsers.py <DOMAIN>/ -dc-ip <IP> -no-pass -request
```

**Vulnerable Signs**
- Hash returned for any account (means `Do not require Kerberos preauthentication` is set)

**Risk:** Offline password cracking (hashcat mode 18200)

---

# Phase 6 — RDP Testing

## 6.1 RDP Security Layer & NLA Check

```bash
nmap --script rdp-enum-encryption -p3389 <IP>
```

**Vulnerable Signs**
- `NLA: Not Supported`
- Only `PROTOCOL_RDP` (Classic) supported — no CredSSP
- TLS not enforced

---

## 6.2 RDP Information Disclosure

```bash
nmap --script rdp-ntlm-info -p3389 <IP>
```

**Signs**
- Domain name, hostname, OS version leaked (Low severity, aids enumeration)

---

## 6.3 RDP BlueKeep & Related CVEs

```bash
# BlueKeep (CVE-2019-0708) — Pre-auth RCE, Windows 7/2008
nmap --script rdp-vuln-ms12-020 -p3389 <IP>

# Use Metasploit scanner (no exploit — detection only)
# msf> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
# msf> set RHOSTS <IP> && run
```

**Vulnerable Signs**
- Positive detection on unpatched Windows 7 / Server 2008

---

## 6.4 RDP Brute-Force Protection Check

```bash
# 3 slow attempts with clearly invalid credentials — observe response behavior
# Do NOT automate without explicit written scope approval for brute forcing
crowbar -b rdp -s <IP>/32 -u administrator -C /usr/share/wordlists/top10.txt -n 1
```

**Vulnerable Signs**
- No lockout after repeated failures
- No delay / rate limiting

---

# Phase 7 — WinRM Testing

## 7.1 WinRM Exposure

```bash
nmap -p5985,5986 -sV <IP>
curl -i http://<IP>:5985/wsman
curl -ik https://<IP>:5986/wsman
```

**Vulnerable Signs**
- Port 5985 (HTTP) open — unencrypted WinRM
- Port 5986 (HTTPS) closed while 5985 is open
- WinRM accessible from non-management networks

**Risk:** Remote command execution over cleartext transport

---

## 7.2 WinRM Authentication Test

```bash
crackmapexec winrm <IP> -u "" -p ""
```

---

# Phase 8 — LDAP / Active Directory Testing

## 8.1 LDAP Anonymous RootDSE

```bash
ldapsearch -x -H ldap://<IP> -s base
ldapsearch -x -H ldap://<IP> -s base namingcontexts
```

**Signs**
- Domain naming context disclosed (Low — aids all subsequent enumeration)

---

## 8.2 Anonymous Directory Enumeration

```bash
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local"
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" "(objectClass=user)"
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" "(objectClass=group)"
```

**Vulnerable Signs**
- User accounts / groups returned anonymously
- Admin accounts visible in output
- Password policies readable unauthenticated

---

## 8.3 LDAP Password Policy Enumeration

```bash
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" "(objectClass=domainDNS)" pwdProperties minPwdLength lockoutThreshold
```

**Vulnerable Signs**
- `minPwdLength` below 12
- `lockoutThreshold` of 0 (no lockout)
- Complexity not enforced

---

## 8.4 LDAPS Certificate Check

```bash
openssl s_client -connect <IP>:636 -showcerts
```

**Vulnerable Signs**
- Self-signed or expired certificate on LDAPS

---

# Phase 9 — DNS Testing

## 9.1 Zone Transfer

```bash
dig axfr domain.local @<IP>
dig axfr @<IP> <DOMAIN>
```

**Vulnerable Signs**
- Full zone records returned — internal infrastructure map disclosed

---

## 9.2 Open Recursion

```bash
nmap -p53 --script dns-recursion <IP>
dig @<IP> google.com
```

**Vulnerable Signs**
- External DNS queries resolved by internal DNS server
- DNS amplification risk

---

## 9.3 DNS Cache Snooping

```bash
nmap --script dns-cache-snoop -p53 --script-args 'dns-cache-snoop.mode=timed' <IP>
```

---

## 9.4 DNSSEC Check

```bash
dig +dnssec SOA <DOMAIN> @<IP>
```

**Vulnerable Signs**
- DNSSEC not enabled on authoritative zones

---

# Phase 10 — SNMP Enumeration

## 10.1 SNMP Community String Check

```bash
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <IP>
snmpwalk -v1 -c public <IP>
snmpwalk -v2c -c public <IP>
nmap -sU -p161 --script snmp-brute <IP>
```

**Vulnerable Signs**
- Community strings `public` or `private` accepted
- System info, running processes, network interfaces disclosed

---

## 10.2 SNMP Information Extraction

```bash
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2   # Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6.3.1.2   # Installed software
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.4.20.1.1     # IP addresses
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.6.13.1.3     # Open TCP ports
```

**Vulnerable Signs**
- Any data returned — full system info disclosure
- Write community string accepted (critical)

---

# Phase 11 — MSSQL Testing (Port 1433)

## 11.1 MSSQL Detection

```bash
nmap -p1433 -sV --script ms-sql-info,ms-sql-config,ms-sql-empty-password <IP>
```

**Vulnerable Signs**
- SQL Server version disclosed
- Empty `sa` password accepted
- Instance name and pipes disclosed

---

## 11.2 MSSQL Brute (3 attempts only, verify lockout first)

```bash
crackmapexec mssql <IP> -u sa -p "" --no-bruteforce
nmap --script ms-sql-brute -p1433 <IP>
```

**Vulnerable Signs**
- Default `sa` credentials (`sa`:`""`, `sa`:`sa`, `sa`:`password`)

---

# Phase 12 — IPv6 Testing (Commonly Missed)

## 12.1 IPv6 Host Discovery

```bash
nmap -6 -sn <IPv6_PREFIX>::/64
nmap -6 <IPv6_ADDR>
```

---

## 12.2 IPv6 Service Scan

```bash
nmap -6 -Pn -p- -sS <IPv6_ADDR>
```

**Vulnerable Signs**
- Services exposed on IPv6 that are firewalled on IPv4
- SMB, RDP, WinRM reachable via IPv6 when blocked on IPv4

---

## 12.3 SLAAC / RDNSS Misconfiguration Check

```bash
# Passive observation for rogue RA
# Document if IPv6 is enabled but unmonitored
nmap -6 --script ipv6-ra-flood --script-args 'ipv6-ra-flood.interface=eth0' <IPv6_ADDR>
```

---

# Phase 13 — LLMNR / NBT-NS / WPAD Poisoning Detection

## 13.1 LLMNR & NBT-NS Active Status Detection

```bash
# Run Responder in ANALYZE mode only (passive — no poisoning)
responder -I <INTERFACE> -A

# Nmap check for LLMNR listener
nmap -p5355 -sU <IP>
```

**Vulnerable Signs**
- LLMNR traffic observed on network
- NBT-NS broadcast queries visible
- Responder captures NTLMv2 hashes in analyze mode

**Risk:** Network-level NTLM hash capture → offline cracking or relay to SMB/LDAP

---

## 13.2 WPAD Misconfiguration Check

```bash
dig wpad.<DOMAIN> @<IP>
curl -s http://wpad.<DOMAIN>/wpad.dat
curl -s http://wpad/wpad.dat
```

**Vulnerable Signs**
- `wpad.dat` file accessible and served
- WPAD DNS record exists but unauthenticated

---

# Phase 14 — Coerce / Relay Attack Surface Assessment

## 14.1 Print Spooler (PrinterBug / SpoolSample)

```bash
# Check if spooler is running (black box indicator)
rpcdump.py <IP> | grep -i spoolss
nmap --script msrpc-enum -p135 <IP>
```

**Vulnerable Signs**
- `MS-RPRN` / `spoolss` interface exposed
- Print Spooler service remotely accessible

**Risk:** Coerced NTLM authentication to attacker-controlled host → NTLM relay / ADCS relay

---

## 14.2 PetitPotam Check (MS-EFSRPC)

```bash
rpcdump.py <IP> | grep -i efsrpc
```

**Vulnerable Signs**
- `MS-EFSRPC` interface exposed on DC

**Risk:** Unauthenticated NTLM coerce → relay to ADCS → domain compromise (pre-patch)

---

# Phase 15 — ADCS (Active Directory Certificate Services) Enumeration

## 15.1 ADCS Detection

```bash
# Check if a CA web enrollment page is exposed
curl -sk https://<IP>/certsrv/
curl -sk http://<IP>/certsrv/

# Check LDAP for CA objects
ldapsearch -x -H ldap://<IP> -b "CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"
```

**Vulnerable Signs**
- `/certsrv/` accessible — Web Enrollment enabled
- HTTP (not HTTPS) Web Enrollment — NTLM relay to ADCS possible (ESC8)
- ADCS accessible without authentication

---

# Phase 16 — Web / Management Panel Testing

## 16.1 Visual Reconnaissance

```bash
gowitness scan -f targets.txt --write-db
# or
eyewitness --web -f urls.txt
```

---

## 16.2 TLS / Certificate Review

```bash
testssl.sh <IP>:443
# or nmap fallback:
nmap --script ssl-cert,ssl-enum-ciphers -p443,8443 <IP>
```

**Vulnerable Signs**
- Expired or self-signed certificate
- TLS 1.0 / TLS 1.1 supported
- SSLv3 enabled (POODLE)
- Weak ciphers (RC4, DES, EXPORT grade, NULL)
- Missing HSTS

---

## 16.3 Security Headers

```bash
nmap --script http-security-headers -p443,8443 <IP>
curl -Ik https://<IP>
```

**Vulnerable Signs**
- Missing `Strict-Transport-Security`
- Missing `X-Frame-Options` / `Content-Security-Policy`
- Missing `X-Content-Type-Options`
- Weak CSP with `unsafe-inline` / `unsafe-eval`
- `Server:` header exposing version

---

## 16.4 HTTP Methods

```bash
nmap --script http-methods -p80,443,8443 <IP>
curl -X OPTIONS https://<IP> -i
```

**Vulnerable Signs**
- `PUT`, `DELETE`, `TRACE`, `CONNECT` methods enabled

---

## 16.5 Directory & Content Discovery

```bash
gobuster dir -u https://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -k -t 30
ffuf -u https://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403
nikto -h https://<IP> -ssl
```

**Vulnerable Signs**
- `/admin`, `/manager`, `/console`, `/phpmyadmin`, `/elmah.axd` accessible
- Backup files (`.bak`, `.old`, `.config`, `.zip`)
- Debug pages (`/trace.axd`, `/elmah.axd`, `/_api`)
- Source code disclosure

---

## 16.6 Default Credentials on Management Panels

```bash
# Test defaults manually:
# IIS Manager: (Windows Auth)
# SCVMM: administrator / (blank or common)
# WSUS: administrator
# Windows Admin Center: (Windows Auth — check if open to internet)
# Hyper-V Manager: (Windows Auth)

whatweb https://<IP>
```

**Vulnerable Signs**
- Default credentials accepted on any panel

---

## 16.7 NTLM Authentication Exposure on HTTP

```bash
curl -Ik https://<IP> | grep -i "WWW-Authenticate"
curl -Ik http://<IP>:5985 | grep -i "WWW-Authenticate"
```

**Vulnerable Signs**
- `WWW-Authenticate: NTLM` on any HTTP endpoint
- Enables NTLM relay / hash capture over HTTP

---

# Phase 17 — Hyper-V Specific Indicators

## 17.1 Hyper-V Port Check

```bash
nmap -p2179,6600 -sV <IP>
```

- Port 2179 = Hyper-V Virtual Machine Connection (VMConnect)
- Port 6600 = Hyper-V Live Migration

**Vulnerable Signs**
- VMConnect port exposed beyond management VLAN
- Live Migration port (6600) externally reachable

---

## 17.2 SCVMM / Windows Admin Center Detection

```bash
nmap -p8172,443,6100 -sV <IP>
curl -sk https://<IP>:6516
curl -sk https://<IP>:443
```

**Vulnerable Signs**
- Management UI exposed on non-management interface
- Version header disclosed
- Unauthenticated access to any management resource

---

## 17.3 Hyper-V Shared Disk / SMB Exposure

```bash
smbmap -H <IP>
# Look for VHD/VHDX shares, ISO shares, cluster storage
```

**Vulnerable Signs**
- Shares containing `.vhd`, `.vhdx`, `.iso` files readable
- Virtual disk files downloadable

---

# Phase 18 — Automated Vulnerability Baseline

## 18.1 OpenVAS / Nessus Scan

```bash
# Run authenticated or unauthenticated scan as per scope
# Nessus: Advanced Scan → Windows / SMB targets
# OpenVAS: System scan policy
```

**Capture:**
- All Critical / High findings
- CVE identifiers
- CVSS scores

---

# Phase 19 — Authentication Testing

> ⚠️ **Only perform with explicit written approval.** Always confirm lockout policy before any login testing.

## 19.1 Username Enumeration

```bash
# Observe response differences manually for valid vs invalid usernames
# RDP, OWA, WinRM, Web login portals
```

**Vulnerable Signs**
- Different error messages / response times for valid vs invalid usernames
- `User not found` vs `Password incorrect` style errors

---

## 19.2 Password Spray (Low-and-Slow — Explicit Approval Only)

```bash
# ONE password attempt per account with spacing to avoid lockout
kerbrute passwordspray --dc <IP> -d <DOMAIN> users.txt 'Password123!'
crackmapexec smb <IP> -u users.txt -p 'Password123!' --continue-on-success
```

**Vulnerable Signs**
- Common passwords accepted (`Password1!`, `Welcome1`, `SeasonYear!`)
- No account lockout triggered

---

## 19.3 Brute-Force Protection Validation

```bash
# 3 invalid attempts, timed manually
# Check for:
# - Delay between failed attempts
# - CAPTCHA
# - Account lockout
# - IP-based rate limiting
```

**Vulnerable Signs**
- No lockout after 5–10 attempts
- No CAPTCHA on internet-facing portals
- No rate limiting by source IP

---

# Phase 20 — Firewall / ACL Surface Assessment

## 20.1 Firewall Rule Inference

```bash
# Identify which ports are filtered vs closed vs open
nmap -Pn -sS --reason -p <TARGET_PORTS> <IP>
```

- `filtered` = firewall dropping
- `closed` = host rejecting (RST)
- `open` = reachable

---

## 20.2 Egress Filter Check

```bash
# Test if host can reach external IPs (do not perform without scope clarity)
# Infer from service behavior and headers
```

**Vulnerable Signs**
- Management services (WinRM, RDP, SMB) reachable from internet
- No network segmentation between management and production interfaces

---
