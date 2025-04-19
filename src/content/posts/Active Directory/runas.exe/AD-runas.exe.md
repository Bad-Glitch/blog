---
title: Credential Injection in Active Directory using runas.exe  
published: 2025-04-18
description: 'Exploring how to leverage runas.exe with /netonly flag for Active Directory credential injection without interactive login'  
image: 'AD-runas.exe.jpeg'
tags: []
category: 'Active Directory Attacks'
draft: false 
lang: 'ar-eng'
---


## 📑 **Table of Contents**

1. [Overview](#overview)  
2. [Why Windows is Essential for AD Attacks](#why-windows-is-essential-for-ad-attacks)  
3. [The `runas.exe` Command and Its Parameters](#2-the-runasexe-command-and-its-parameters)  
    - [Basic Syntax](#basic-syntax)  
    - [Explanation of Parameters](#explanation-of-parameters)  
    - [Example Usage](#example-)  
4. [Practical Use of `runas.exe` for AD Credential Injection](#3-practical-use-of-runasexe-for-ad-credential-injection)  
    - [Accessing Shared Folders](#accessing-shared-folders)  
    - [Authenticating to SQL Server](#authenticating-to-sql-server)  
    - [Web Application Authentication](#web-application-authentication)  
    - [SQL Management Studio Example](#example-of-running-sql-management-studio)  
5. [Verifying the Success of Credential Injection](#4-verifying-the-success-of-credential-injection)  
6. [DNS Configuration for Network Authentication](#5-dns-configuration-for-network-authentication)  
7. [Authentication Types: Kerberos vs. NTLM](#6-authentication-types-kerberos-vs-ntlm)  
8. [Post-Injection Exploitation Scenarios](#7-post-injection-exploitation-scenarios)  
    - [Network Shares](#network-shares)  
    - [SQL Server Authentication](#sql-server-authentication)  
    - [Enumerating Active Directory Objects](#enumerating-active-directory-objects)  


## **Credential Injection in Active Directory using runas.exe**

### **Overview**

When conducting penetration testing or red team assessments against an Active Directory (AD) environment, there are scenarios where valid credentials are obtained, but interactive access to a domain-joined machine is unavailable. In such cases, **Credential Injection** techniques allow an attacker to utilize the credentials without logging into a domain-joined system.

One of the most effective ways to achieve this on a Windows machine is by leveraging the built-in `runas.exe` utility with the `/netonly` flag.

## **Why Windows is Essential for AD Attacks**

While Linux-based tools (e.g., Kali Linux) provide powerful enumeration capabilities, some Windows-native functionalities are crucial for interacting with Active Directory environments. One such functionality is `runas.exe`, which allows an attacker to impersonate a domain user and execute commands with their privileges over the network.

`runas.exe` is a legitimate Windows binary that allows a user to execute a program as another user. It is primarily used to run applications or commands with different user credentials, making it a powerful tool for penetration testers and attackers alike.

In the context of Active Directory (AD) attacks, `runas.exe` can be used to inject **Active Directory credentials** into a non-domain-joined machine or a machine where the attacker has local administrative privileges but lacks the necessary AD permissions to perform certain actions.

The key advantage of `runas.exe` in this scenario is its ability to **apply the AD credentials solely for network communication** (through the `/netonly` flag), while the local machine remains under the attacker’s current user context.

### **2. The `runas.exe` Command and Its Parameters**

To effectively use `runas.exe`, it's essential to understand how its syntax works and what each parameter means.

### **Basic Syntax**

```jsx
runas.exe /netonly /user:<domain>\<username> <command>
```

### **Explanation of Parameters:**

- **`/netonly`**:
    - This flag is used to instruct `runas.exe` that the credentials provided should only be used for **network authentication** (to authenticate against resources such as file shares or domain services).
    - The local machine remains in the context of the current user, so the attacker doesn't gain elevated privileges on the local system.
- **`/user`**:
    - This specifies the **domain and username** in the format `<domain>\<username>`.
    - Always use the **Fully Qualified Domain Name (FQDN)** of the domain instead of the NetBIOS name for better name resolution in the domain environment.
- **`<command>`**:
    - The command specifies the program that will run with the injected credentials. Common choices are **cmd.exe** or **PowerShell**, but you can use any executable that suits your needs, depending on what you want to accomplish with the injected credentials.

### **Example :**

```jsx
runas.exe /netonly /user:example.com\user123 cmd.exe
```

- This command runs `cmd.exe` under the credentials of **user123** in the domain **example.com**.
- The system will prompt for the **password** for `user123`, and once entered, the command prompt (`cmd.exe`) will open with the credentials loaded into memory.

---

### **3. Practical Use of `runas.exe` for AD Credential Injection**

Once the credentials are injected into memory, they can be used for **network-based authentication** across the domain. The injected credentials will allow you to authenticate to domain resources, but not elevate privileges on the local system.

### **Practical Use Cases:**

- **Accessing Shared Folders**:
    
    Using `runas.exe` to authenticate as a domain user lets you access shared network folders and services that are otherwise restricted by the local system’s user context.
    
    ```jsx
    dir \\<domain>\share
    ```
    
    - This will allow you to enumerate and interact with **network shares** and **SYSVOL directories** without being a domain-joined machine.
    - **Authenticating to SQL Server**:
        
        In many environments, **SQL Server** can be configured to use **Windows Authentication**, allowing domain users to connect without a separate SQL login. By injecting valid AD credentials, an attacker can gain access to SQL Server instances that rely on Windows Authentication.
        
        - For example, you could run **SQL Management Studio** (`ssms.exe`) using `runas.exe` and authenticate to the SQL server as the injected user, bypassing the need for separate SQL credentials.
    - **Web Application Authentication**:
        
        Many internal web applications use **NTLM** (Windows Integrated Authentication) to authenticate users. If you have domain credentials loaded, you can interact with these applications without needing to enter credentials manually. Just by opening a browser session from a `runas`-spawned command prompt, NTLM authentication will automatically pass the AD credentials.
        
    
    ### **Example of Running SQL Management Studio**:
    
    ```jsx
    runas.exe /netonly /user:example.com\user123 ssms.exe
    ```
    
    This command would launch **SQL Management Studio** (`ssms.exe`) under the **user123** credentials, allowing access to any SQL servers the user has permissions to interact with.
    
    ---
    
    ### **4. Verifying the Success of Credential Injection**
    
    After successfully injecting the credentials, the next step is to verify that they are being used properly and that the network authentication is functioning.
    
    ### **Testing Network Authentication**
    
    One of the most reliable ways to test if the credentials were correctly injected is by accessing the **SYSVOL directory** on the domain controller. The SYSVOL share contains important **Group Policy Objects (GPOs)** and other domain-related files, which are accessible to all domain users.
    
    You can use the following command to test:
    
    ```jsx
    dir \\<DomainController_FQDN>\SYSVOL\
    ```
    
    - If the command successfully lists the contents of the `SYSVOL` directory, it indicates that the credentials are working correctly and you can now interact with domain resources.
    - If the command fails, the credentials might be incorrect, or there could be a permissions issue.
    
    ---
    
    ### **5. DNS Configuration for Network Authentication**
    
    To ensure smooth communication with domain resources (such as the **Domain Controller**), it's critical to have **proper DNS resolution**. Typically, the **DNS server** should be set to the **Domain Controller** itself.
    
    ### **Manually Configuring DNS**
    
    If DNS is not automatically configured, you can manually set the DNS server on the machine to point to the **Domain Controller’s IP**:
    
    ```jsx
    $dnsip = "<DomainController_IP>"
    $index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
    ```
    
    After setting the DNS, use the following command to verify the DNS configuration:
    
    ```jsx
    nslookup <domain_FQDN>
    ```
    
    This ensures that the machine can properly resolve domain names and communicate with the Domain Controller.
    
    ---
    
    ### **6. Authentication Types: Kerberos vs. NTLM**
    
    An important consideration when using `runas.exe` for credential injection is the **authentication type** used for network communication.
    
    - **Kerberos Authentication**:
        - This is the preferred method for authenticating users to domain resources. When you use the **FQDN** of a domain controller (e.g., `\\<DC_FQDN>\SYSVOL`), the system will try to authenticate using **Kerberos**.
    - **NTLM Authentication**:
        - If you provide the **IP address** of the domain controller instead of the FQDN (e.g., `\\<DC_IP>\SYSVOL`), the authentication will fall back to **NTLM**. NTLM is less secure than Kerberos, but this fallback method can be useful in situations where you want to avoid Kerberos authentication (e.g., to bypass detection during a red team exercise).
    
    ### **Example:**
    
    ```jsx
    dir \\<DC_FQDN>\SYSVOL
    ```
    
    This will use **Kerberos**.
    
    ```jsx
    dir \\<DC_IP>\SYSVOL
    ```
    
    This will use **NTLM**.
    
    ---
    
    ### **7. Post-Injection Exploitation Scenarios**
    
    Once the credentials are successfully injected, a variety of post-exploitation actions can be carried out using those credentials.
    
    ### **Examples of Post-Exploitation**
    
    - **Network Shares**:
        
        Attackers can access **file shares**, read and exfiltrate sensitive information, and potentially upload malicious files if the user has write permissions.
        
    - **SQL Server Authentication**:
        
        Using **Windows Authentication**, an attacker can access SQL Servers to dump sensitive data, such as **password hashes** or confidential business data.
        
    - **Enumerating Active Directory Objects**:
        
        Once authenticated, attackers can start enumerating **AD objects** (users, groups, machines), which can reveal valuable information about the domain structure and potential targets for further exploitation.