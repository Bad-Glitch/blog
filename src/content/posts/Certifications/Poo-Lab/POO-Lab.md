---
title: HTB P.O.O Lab Review – Level 1 Red Team Operator
published: 2025-04-17
updated: 2025-04-17
description: 'An in-depth review of the P.O.O - Level 1 Red Team Operator lab.'
image: 'poo-lab.png'
tags: [HTB Pro Labs]
category: 'Certifications'
draft: false 
lang: 'ar-eng'
---

## Table of Contents

1. [What is P.O.O?](#what-is-poo)  
2. [Lab Scenario](#lab-scenario)  
3. [Skills Required](#skills-required)  
4. [Lab Objectives](#lab-objectives)  
5. [Lab Structure](#lab-structure)  
6. [Key Attack Phases](#key-attack-phases)  
7. [What You Will Gain](#what-you-will-gain)  
8. [Target Audience](#target-audience)  
9. [Essential Resources](#essential-resources)  
10. [Conclusion](#conclusion)  

> **⚠️ Caution:** #FreePalestine

## **MINI PRO LAB: P.O.O - Level 1 Red Team Operator** **Lab Overview:**

The **P.O.O (Professional Offensive Operations)** Level 1 Red Team Operator lab is designed to challenge and enhance your skills in **enumeration**, **lateral movement**, and **privilege escalation** within a small Active Directory (AD) environment. The lab simulates a modern corporate infrastructure with the latest OS technologies, providing a challenging but rewarding experience for penetration testers and red teamers looking to refine their offensive tradecraft.

---

### **Lab Scenario:**

The objective of the **P.O.O.** lab is to compromise the **perimeter host**, escalate privileges within the system, and ultimately compromise the entire **domain** while collecting **five flags** throughout the process. As you work through the environment, you will encounter a mixture of **Linux**, **Windows**, and **Active Directory** components that will require you to navigate multiple attack vectors and technologies.

---

## **Skills and Knowledge Required:**

The P.O.O. lab is geared toward penetration testers and red teamers who have a fundamental understanding of offensive security concepts but wish to build upon their existing knowledge in a hands-on environment.

**Key Skills:**

- **Penetration Testing Methodologies**: Familiarity with common penetration testing techniques (e.g., information gathering, vulnerability scanning, exploitation, etc.).
- **Active Directory**: Basic understanding of Active Directory structure, services, and attack methods.
- **Linux & Windows Operating Systems**: Knowledge of system-level operations and exploitation techniques on both Linux and Windows platforms.
- **Web Application Attacks**: Understanding of common web application vulnerabilities and attack methods, such as SQL injection, XSS, and command injection.
- **Active Directory Enumeration**: Knowledge of how to enumerate users, groups, and permissions within Active Directory environments.

---

## **Lab Objectives:**

Throughout the **P.O.O. Level 1** lab, your primary goal is to gain initial access to the network and move from **user-level** access to **domain admin** privileges. This involves exploiting vulnerabilities within the **perimeter host**, leveraging **local privilege escalation**, performing **lateral movement**, and eventually **compromising the domain**. Along the way, you will encounter **several flags** that demonstrate your progress.

### **What You Will Learn:**

By the end of the lab, you will be able to:

1. **Enumerate Active Directory**: Collect key information from the domain controller, including users, groups, and permissions.
2. **Exploiting Active Directory Vulnerabilities**: Learn how to escalate from a low-privileged user account to full domain access.
3. **Lateral Movement**: Use techniques to move across systems in the network to escalate your privileges.
4. **Local Privilege Escalation**: Gain higher-level access on the target machine through privilege escalation techniques.
5. **Situational Awareness**: Understand the network environment and its components to guide your offensive strategies.
6. **Web Application Enumeration**: Discover and exploit common web application vulnerabilities as part of the broader penetration testing approach.

---

## **Lab Structure:**

The **P.O.O.** lab contains a small Active Directory environment with **2 machines** that simulate various components of a network. One of these machines will be the perimeter host, while the second will serve as a **domain controller** or a machine critical for escalation.

1. **Perimeter Host (Target Machine)**: The initial point of entry for attackers. Typically a workstation or server exposed to the internet, which you will need to exploit to gain access.
2. **Domain Controller (DC)**: The heart of the network, where all user and group information resides. This machine is the ultimate goal for compromise.

### **Starting Point:**

The lab begins with a **low-privileged foothold** on the perimeter host. Your task is to gain **local administrator access** through a combination of web application vulnerabilities, misconfigurations, and brute force attacks.

---

## **Key Phases of the Lab:**

### 1. **Initial Access:**

You’ll start by gaining access to the perimeter host. This is often done through:

- **Exploiting Web Application Vulnerabilities**: Identifying weaknesses in the perimeter web applications (SQLi, XSS, etc.).
- **Phishing**: If email access is available, phishing can also be a vector for initial access.

### 2. **Enumeration:**

Once inside, the next step is to gather information:

- **User Enumeration**: Using tools like `Netcat`, `Netstat`, `PowerView`, and `Enum4linux`, you will find valuable information about the users and groups.
- **Active Directory Enumeration**: Using tools like **BloodHound**, **PowerView**, and **ADRecon**, you can map out users, permissions, trusts, and attack paths.

### 3. **Privilege Escalation:**

Now that you have limited access, the focus shifts to escalating privileges:

- **Local Privilege Escalation**: Exploit local misconfigurations, insecure file permissions, or unpatched vulnerabilities to elevate your access on the system.
- **Bypassing UAC**: Use tools like **Mimikatz** or **PowerShell Empire** to bypass User Account Control (UAC) and escalate privileges.

### 4. **Lateral Movement:**

After escalating privileges on one machine, you can attempt to move to other machines within the network:

- **SMB/NetSession**: Use SMB (Server Message Block) to move laterally between Windows hosts.
- **RDP or PsExec**: Use RDP or **PsExec** for remote execution of commands.
- **Kerberos & Pass-The-Hash (PTH)**: Exploit weak configurations or stolen credentials to authenticate to other machines.

### 5. **Domain Compromise:**

The ultimate goal of the P.O.O. lab is to compromise the **Domain Controller**. Achieving domain admin privileges can be done by:

- **Kerberoasting**: Stealing service tickets for service accounts in AD.
- **Golden Ticket**: Use a forged Kerberos TGT to gain unrestricted access to the domain.

---

## **What You Will Gain from the Lab:**

- **Hands-on experience** with **Active Directory attacks**, especially related to enumeration, privilege escalation, and lateral movement.
- **Deep understanding** of how Windows-based networks operate and how they can be exploited.
- **Knowledge of common tools** and techniques used by Red Teamers to gain control over a network.
- **Critical thinking and troubleshooting skills** that will help in real-world engagements, where every move counts and there is no single path to success.

---

**Who is P.O.O. for?**

The P.O.O. lab is ideal for those who are looking to:

- Hone their **Red Team** skills, especially in the area of **Active Directory**.
- Learn **privilege escalation** and **lateral movement** techniques in a controlled, lab-based environment.
- Gain practical experience with **enumeration** and **exploit techniques** in both **Linux and Windows** systems.
- Understand **web application vulnerabilities** and how they can be leveraged for internal network access.

---

## **Attitude and Mentality:**

To succeed in this lab, you will need:

- **Patience and perseverance**: Red Teaming often requires multiple attempts and creative approaches.
- **A willingness to conduct research**: Research new exploits, techniques, and tools that could help you achieve your objectives.
- **Critical thinking**: Always think outside the box and try different paths if you get stuck.

---

Here are some references to help you prepare for the **P.O.O. Level 1 Red Team Operator** lab. These resources will cover topics such as **Active Directory attacks**, **privilege escalation**, **lateral movement**, and **enumeration**.

### 1. **Book: "The Red Team Field Manual (RTFM)"**

- **Author**: Ben Clark
- **Summary**: This book is a practical reference containing many tools and techniques for **Red Teaming**. It covers **enumeration**, **lateral movement**, **exploitation**, and **system control**.
- **Benefits**: It's a concise manual focused on the essential tools and processes used in environments like **Active Directory**.
- **Link**: [Red Team Field Manual](https://www.amazon.com/Red-Team-Field-Manual-RTFM/dp/1943191124)

### 2. **Course: "Active Directory Attacks" on Udemy**

- **Provider**: Udemy
- **Summary**: This course covers advanced **Active Directory** attacks such as **enumeration**, **privilege escalation**, and **lateral movement**.
- **Benefits**: Practical course full of real-world examples, including the use of tools like **PowerView** and **BloodHound**.
- **Link**: Active Directory Attacks on Udemy

### 3. **Course: "Red Team Tactics, Techniques, and Procedures (TTPs)" on Offensive Security**

- **Provider**: Offensive Security
- **Summary**: This comprehensive course on **Red Teaming** focuses on **enumeration**, **lateral movement**, and **privilege escalation** on both **Windows** and **Active Directory** systems.
- **Benefits**: Covers modern attack techniques like **Pass-the-Hash** and **Kerberoasting**.
- **Link**: [Offensive Security Red Team TTPs](https://www.offensive-security.com/)

### 4. **Tools like PowerView and BloodHound**

- **PowerView**: A useful tool for **Active Directory enumeration**. It lets you interact with **Active Directory** and extract valuable information.
- **BloodHound**: A great tool for understanding relationships within **Active Directory** and discovering vulnerabilities that can be exploited.
- **Link**: [PowerView on GitHub](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- **Link**: [BloodHound on GitHub](https://github.com/BloodHoundAD/BloodHound)

### 5. **Book: "Practical Privilege Escalation"**

- **Author**: Chris "Hacks" Sutherland
- **Summary**: This book covers practical strategies for **privilege escalation** on **Windows** systems, with examples and open-source tools.
- **Benefits**: Covers tools like **Mimikatz** and **PsExec**, which are critical for privilege escalation and lateral movement.
- **Link**: [Practical Privilege Escalation](https://www.amazon.com/Practical-Privilege-Escalation-Windows-Applications/dp/1801812745)

### 6. **Course: "Windows Privilege Escalation" on TryHackMe**

- **Provider**: TryHackMe
- **Summary**: This course focuses on **privilege escalation** on **Windows** systems, covering techniques like **UAC bypass**, **DLL hijacking**, and **exploiting misconfigurations**.
- **Benefits**: Practical hands-on course to apply concepts in live environments.
- **Link**: Windows Privilege Escalation on TryHackMe

### 7. **Course: "Active Directory Hacking" on Pluralsight**

- **Provider**: Pluralsight
- **Summary**: This course dives into **Active Directory** exploitation, focusing on attacks such as **Kerberos**, **Pass-the-Hash**, and **Golden Ticket** attacks.
- **Benefits**: Includes case studies and real-world examples for interacting with **Active Directory** environments.
- **Link**: Active Directory Hacking on Pluralsight

### 8. **Online Articles and Resources:**

- **SecTools.net**: A website that lists popular tools used for **pen testing** and **Active Directory attacks**.
- **The Hacker News**: A news site that covers modern hacking techniques, including **Active Directory** exploitation.
- **Hacking Articles**: Provides detailed tutorials on **Active Directory hacking** and **Windows penetration testing**.
- **Link**: [SecTools.net](https://sectools.org/)
- **Link**: [Hacking Articles](https://www.hackingarticles.in/)

---

### 9. **YouTube Channels:**

- **LiveOverflow**: Offers great content on practical hacking and **Red Teaming**, with videos on **Active Directory** attacks and exploitation.
- **IppSec**: Provides breakdowns of various **CTF challenges** that often include **enumeration** and **privilege escalation** techniques.

---

### 10. **Books and Articles:**

- **Book: "The Web Application Hacker's Handbook"**: Although it's web-focused, it includes advanced tools and techniques useful for attacking local systems.
- **Article: "Active Directory Attacks and Defense"**: Explains **Active Directory** attack methods and how to defend against them.

---

### Additional Resources:

- **Active Directory Attacks Cheat Sheet**: Keep a cheat sheet for **enumeration** and **exploitation** handy. It can help you understand how to leverage **Active Directory** misconfigurations.

By utilizing these resources, you will gain a solid understanding of the key techniques required for the **P.O.O. Level 1** lab, especially in **Active Directory exploitation**, **privilege escalation**, and **lateral movement**. Make sure to practice these techniques in real environments to gain practical experience.

## **Conclusion:**

By the time you complete **P.O.O. Level 1**, you will have gained a **strong foundational understanding of Active Directory attacks**, learned how to move from **initial foothold to full domain compromise**, and refined your skills in **enumeration, lateral movement**, and **privilege escalation**.

This lab provides a great starting point for anyone looking to enhance their offensive security skills in a **realistic**, **hands-on**, and **challenging** environment.