---
title: HTB RastaLabs Review – Advanced Red Team Operations
published: 2025-02-01
updated: 2025-02-01
description: 'An in-depth review of the RastaLabs advanced Red Team simulation environment.'
image: 'rasta-lab.png'
tags: [HTB Pro Labs]
category: 'Certifications'
draft: false 
lang: ''
---
## Table of Contents

1. [Lab Architecture & Scenario](#lab-architecture--scenario)  
2. [Initial Access & Payload Crafting](#initial-access--payload-crafting)  
3. [Situational Awareness](#situational-awareness)  
4. [Active Directory Enumeration](#active-directory-enumeration)  
5. [Credential Access & Token Manipulation](#credential-access--token-manipulation)  
6. [Lateral Movement Techniques](#lateral-movement-techniques)  
7. [Key Takeaways](#key-takeaways)  
8. [References](#references)  
9. [Conclusion](#conclusion)  

> **⚠️ Caution:** #FreePalestine

## **Lab Architecture & Scenario**

RastaLabs provides you with a simulated real-world environment that mimics a company's Active Directory domain, interconnected with various systems and users having different privilege levels.

### **Objective:**

The goal is to start from a low-privilege foothold and progressively escalate privileges until you achieve complete domain control. This must be done using stealthy methods.

 **What Makes RastaLabs Special:**

- There are no predefined objectives or flags.
- It’s not just about exploitation; you need to be **stealthy** and use native Windows features to avoid detection.
- Every progress you make results in new access (User/Host/Domain privilege escalation).

### **Lab Setup:**

The RastaLabs environment consists of **15 machines** that represent various roles and privilege levels within the domain. Some of these machines include workstations, domain controllers, file servers, and target services, providing a comprehensive and dynamic environment for Red Team operations.

---

 **Initial Access (Phishing Scenario)**

### ⛳️ **How It Began:**

RastaLabs simulates attack vectors like spear-phishing emails or malicious macros in an Excel file

- I had to **build payloads that bypass AVs** (using `Donut`, `Sharpshooter`, `Shellter`, `Nim`, etc.).
- I had to deal with multiple AV/EDR solutions and learned how to create stealthy payloads using:
    - AMSI bypass techniques
    - Inline shellcode execution (via `sRDI`, `Nim`, `C#`)
    - Process injection via `CreateRemoteThread`, `QueueUserAPC`

### **Key Takeaway:**

> Not everything works with Empire or Metasploit, so you need to develop your own custom tradecraft!
> 

---

## **Situational Awareness**

The first step after gaining access is to understand where you are and who you’re dealing with.

### Tools I Used:

- `whoami /groups`, `hostname`, `ipconfig`, `netstat`, `query user`, `systeminfo`
- **PowerView.ps1** – used carefully for AD recon
- `Seatbelt.exe` – a powerful tool for gathering information about the system (AVs, UAC, autoruns, etc.)

### What I Discovered:

- The system had an AV running → I had to use native or obfuscated commands for recon.
- Mapped drives → hint at file share servers.
- My account was low-privileged within the Domain → no direct access to the Domain Controller (DC).

---

## **Active Directory Enumeration**

### 🛠 **Tools Used:**

- PowerView (but modified to avoid detection)
- `net`, `dsquery`, `nltest`, `Get-NetUser`, `Get-NetGroupMember`, ...
- Manual LDAP queries
- BloodHound (with stealthy collection like ACL-only or Session-only)

### **Techniques:**

- Enumerated **users, groups, sessions, ACLs, GPOs**
- Found weak accounts (helpdesk, svc accounts, etc.)
- Discovered misconfigured ACLs and **Unconstrained delegation** → obvious target for lateral movement.

---

## **Credential Access & Token Manipulation**

### Methods Used:

- `Mimikatz`: to dump credentials from LSASS (by bypassing AVs beforehand)
- `Rubeus`:
    - Kerberoasting (service accounts)
    - Overpass-the-Hash (pass NTLM hash → TGT)
    - Ticket Harvesting
- `SharpDump`, `Dumpert`, `SafetyKatz` (bypassing EDRs)

 **Significant Success:**

- I managed to get a TGT ticket for an Admin account from a session that wasn’t immediately visible → used `Incognito` + `Rubeus ptt`.

---

## **Lateral Movement**

I used multiple methods:

# Reference Links

- https://adsecurity.org/
- http://blog.harmj0y.net/
- https://chryzsh.gitbooks.io/darthsidious/
- https://www.ired.team/
- https://www.mdsec.co.uk/blog/
- https://pentestlab.blog/
- https://www.trustedsec.com/blog/
- https://rastamouse.me/blog/