---
title: 'Exploiting LLMNR Poisoning: From Hash Theft to Domain Compromise'
published: 2025-04-22
description: 'Deep dive into LLMNR poisoning attacks, demonstrating how attackers abuse the protocol for MITM attacks, credential theft, and lateral movement.'
image: ''
tags: []
category: 'Privilege Escalation'
draft: false 
lang: 'ar-eng'
---
# Table of Contents
- [Overview](#overview)
- [How LLMNR Poisoning Works](#how-llmnr-poisoning-works)
  - [LLMNR Request](#llmnr-request)
  - [Attacker Intercepts the Request](#attacker-intercepts-the-request)
  - [Poisoning the Response](#poisoning-the-response)
  - [Victim Connects to Attacker](#victim-connects-to-attacker)
  - [Data Theft or Further Exploitation](#data-theft-or-further-exploitation)
- [Tools Used for LLMNR Poisoning](#tools-used-for-llmnr-poisoning)

---

## Overview

LLMNR (Link-Local Multicast Name Resolution) is a protocol used in local networks (LAN) to resolve hostnames to IP addresses when DNS is unavailable. LLMNR allows devices to resolve names on a local network, but it can be exploited by attackers to perform **man-in-the-middle (MITM)** attacks and steal sensitive data.

---

## How LLMNR Poisoning Works

1. **LLMNR Request**
   - A device (e.g., a computer) tries to reach another device using a hostname (e.g., `server.local`) but fails to resolve it using DNS.
   - The device sends an LLMNR query to the local network, requesting the IP address for the hostname.
2. **Attacker Intercepts the Request**
   - The attacker, monitoring the network with tools like **Responder** or **Ettercap**, intercepts the LLMNR request.
3. **Poisoning the Response**
   - The attacker responds to the LLMNR request with a spoofed reply, claiming to be the requested hostname (e.g., `server.local`).
   - The response contains the attacker's IP address instead of the legitimate device's IP.
4. **Victim Connects to Attacker**
   - The victim device, believing the attacker is the requested device, connects to the attacker's machine.
5. **Data Theft or Further Exploitation**
   - The attacker can now perform various actions, such as stealing **NTLM hashes**, capturing **SMB** credentials, or launching a **MITM** attack to intercept sensitive data.

---

## Tools Used for LLMNR Poisoning

- **Responder**: A popular tool used for LLMNR poisoning. It listens for LLMNR requests and responds with malicious replies to capture credentials.
- **Ettercap**: Another tool that can be used for MITM attacks, including LLMNR poisoning, to intercept and manipulate traffic between the victim and the network.


---

**`Happy Hacking Broo`**

---