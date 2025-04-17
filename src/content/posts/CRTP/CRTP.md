---
title: CRTP Review – Certified Red Team Professional
published: 2025-04-17
updated: 2025-04-17
description: 'A comprehensive review of the Certified Red Team Professional (CRTP) exam.'
image: 'CRTP.png'
category: 'Certifications'
draft: false 
lang: 'ar-eng'
---

## Table of Contents

1. [Intro](#intro)  
2. [Objectives of the CRTP Certification](#objectives-of-the-crtp-certification)  
3. [Prerequisites](#prerequisites)  
4. [Key Tools & Techniques Covered](#key-tools--techniques-covered)  
5. [Course Content Breakdown](#course-content-breakdown)  
6. [Exam Format](#exam-format)  
7. [Resources](#resources)  
8. [Conclusion](#conclusion)

> **⚠️ Caution:** #FreePalestine

## Intro

The **Certified Red Team Professional (CRTP)** is an intermediate-level, hands-on certification offered by **Pentester Academy** (now under **INE**). It focuses entirely on attacking Windows Active Directory environments—perfect for those specializing in internal network penetration testing and Red Team ops.

---

## Objectives of the CRTP Certification

- Understand the structure and weaknesses of Active Directory.
- Perform real-world internal AD attacks using Red Team techniques.
- Use tools like **PowerView**, **Rubeus**, **Mimikatz**, and **BloodHound** effectively.
- Exploit common AD misconfigurations:
  - Unconstrained Delegation
  - Kerberoasting
  - AS-REP Roasting
  - Abusing ACLs and GPOs
- Perform **lateral movement** and **persistence** techniques.
- Map Tactics, Techniques, and Procedures (TTPs) to the **MITRE ATT&CK** framework.

---

## Prerequisites

Before diving into CRTP, it’s recommended you have:

- A solid understanding of **Windows OS** fundamentals.  
- Basic **networking concepts** (TCP/IP, DNS).  
- Familiarity with **Active Directory**.  
- Basic **PowerShell scripting** experience.  
- Background in **penetration testing** is highly recommended.

---

## Key Tools & Techniques Covered

| Tool/Technique     | Purpose                                      |
|--------------------|----------------------------------------------|
| **PowerView**      | AD enumeration & recon                       |
| **Rubeus**         | Kerberos attacks, ticket abuse               |
| **Mimikatz**       | Credential dumping, Pass-the-Hash/Ticket     |
| **Impacket**       | Remote command execution, relay attacks      |
| **BloodHound**     | Graph-based privilege escalation & analysis  |
| **PowerShell Empire** | C2 management & persistence              |
| **SharpHound**     | Data collection for BloodHound               |

---

## Course Content Breakdown

- Active Directory Enumeration Basics  
- User Hunting & Local Privilege Escalation  
- **Kerberos Attacks**:
  - AS-REP Roasting  
  - Kerberoasting  
- Abusing ACLs & GPOs  
- Lateral Movement:
  - Pass-the-Hash / Pass-the-Ticket  
  - PSExec / WMI / WinRM  
- Ticket Attacks:
  - Golden Ticket  
  - Silver Ticket  
- Persistence:
  - Scheduled Tasks  
  - Registry  
  - WMI Event Subscriptions  
- Defensive Evasion & AV Bypass

---

## Exam Format

- **24‑hour hands‑on practical exam**: Exploit a full AD environment, escalate to **Domain Admin**.  
- **48 hours to submit** a professional Red Team–style report.  
- **1‑month lab access** (extendable).  
- Fully scenario‑based—no multiple‑choice.

---

## Resources

### 🔗 Written Notes & Guides

- [CRTP Notes by 0xStarlight](https://github.com/0xStarlight/CRTP-Notes)  
- [MY CRTP Notes by Abhinandan](https://github.com/Abhinandan-Khurana/MY-CRTP-Notes)  
- [0xd4y CRTP Blog](https://0xd4y.com/2023/04/05/CRTP-Notes/)

### 💻 TryHackMe Labs

- [Windows and Active Directory Fundamentals](https://tryhackme.com/module/windows-and-active-directory-fundamentals)  
- [Hacking Windows Module](https://tryhackme.com/module/hacking-windows-1)

### 🔧 GitHub Tools

- [PowerView (PowerSploit)](https://github.com/PowerShellMafia/PowerSploit)  
- [Rubeus](https://github.com/GhostPack/Rubeus)  
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

### 🎯 Practice Labs

- TryHackMe: *Attacktive Directory Room*  
- Hack The Box: *Active Directory Labs*

---

## Conclusion

**CRTP** is more than a certification—it’s a realistic, hands-on journey into enterprise AD exploitation and Red Team tradecraft. Whether you’re targeting a Red Team role or sharpening your AD-attack skills, CRTP stands out as a transformative investment.