---
title: "The VSSAdmin Dumping Attack: Extracting Sensitive Data via Shadow Copies"
published: 2025-04-20
description: 'Exploiting Windows Volume Shadow Copies to extract deleted files and sensitive data while evading detection.'
image: '1.webp'
tags: [ Windows PrivEsc]
category: 'Privilege Escalation'
draft: false 
lang: 'ar-eng'

---

# Table of Contents

- [The VSSAdmin Dumping Attack](#the-vssadmin-dumping-attack)
  - [Key Concepts](#key-concepts)
  - [Steps for the Attack](#steps-for-the-attack)
    - [1. Check for Existing Shadow Copies](#1-check-for-existing-shadow-copies)
    - [2. Create a New Shadow Copy (if none exist)](#2-create-a-new-shadow-copy-if-none-exist)
    - [3. Locate the Shadow Copy](#3-locate-the-shadow-copy)
    - [4. Copy Data from the Shadow Copy](#4-copy-data-from-the-shadow-copy)
    - [5. Extract Sensitive Data](#5-extract-sensitive-data)
  - [Execution Example](#execution-example)
  - [Why This Attack Is Dangerous](#why-this-attack-is-dangerous)

---
# The VSSAdmin Dumping Attack

The **VSSAdmin Dumping Attack** exploits the **Volume Shadow Copy Service (VSS)** in Windows to create or access shadow copies of the system's volumes. These shadow copies contain backup data, which can include sensitive files that may not be available on the live system. Attackers use this service to extract sensitive data without detection.

---

## Key Concepts

1. **Volume Shadow Copy Service (VSS):**
   - VSS is a feature in Windows that allows users to create backup copies of files or volumes even when they are in use.
   - These backup copies are known as **Shadow Copies**.
   - Shadow copies are often created automatically by the system or can be manually triggered.
2. **VSSAdmin Tool:**
   - **VSSAdmin** is a command-line utility in Windows used to manage shadow copies.
   - It allows users to create, list, and delete shadow copies on the system.

---

## Steps for the Attack

### 1. Check for Existing Shadow Copies

- First, the attacker needs to check if there are any existing shadow copies on the target system. This can be done by running the following command:

```powershell
vssadmin list shadows
```

- This command will display all existing shadow copies, including their creation time and associated volume.

### 2. Create a New Shadow Copy (if none exist)

- If no shadow copies are found, the attacker can create a new one using the following command:

```powershell
vssadmin create shadow /for=C:
```

- Replace `C:` with the desired drive letter if the target drive is different.
- This command creates a new shadow copy of the specified volume (in this case, the C: drive).

### 3. Locate the Shadow Copy

- After creating or identifying an existing shadow copy, the attacker needs to locate the data in the shadow copy.
- The shadow copy is mounted at a specific location in the file system. This location is typically:

```powershell
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\
```

- Where `X` is the number assigned to the shadow copy.

### 4. Copy Data from the Shadow Copy

- To extract files from the shadow copy, the attacker can use a file copy utility like **Robocopy** or **Xcopy** to copy data from the shadow copy to a different location on the system:

```powershell
robocopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\path\to\files C:\path\to\destination
```

- Replace `X` with the appropriate shadow copy number and `path\to\files` with the path to the files you want to copy.
- The attacker can now access sensitive files from the shadow copy that may have been deleted or modified on the live system.

### 5. Extract Sensitive Data

- The attacker can now explore the copied files to find sensitive information such as passwords, documents, or any other confidential data that may have been stored in the backup.

---

## Execution Example

Here's an example of how the attack might look in practice:

1. **List existing shadow copies:**

```powershell
vssadmin list shadows
```

2. **Create a new shadow copy (if none exist):**

```powershell
vssadmin create shadow /for=C:
```

3. **Identify the shadow copy path:**

```powershell
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

4. **Copy files from the shadow copy:**

```powershell
robocopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\C:\Users\Administrator\Documents C:\Users\Attacker\Desktop
```

## Why This Attack Is Dangerous

1. **Access to Deleted Files:**
   - Shadow copies may contain files that have been deleted from the live system but still exist in the backup.
2. **Sensitive Data Exposure:**
   - Backup files may contain sensitive data, including passwords, configuration files, and other confidential information.
3. **Bypass Security Measures:**
   - This attack can bypass file deletion and security measures that are intended to protect data on the live system.
4. **Low Detection Risk:**
   - Since shadow copies are created by the system itself, this attack can be difficult to detect, especially if the attacker has elevated privileges.

# Table of Contents

- [The VSSAdmin Dumping Attack](#the-vssadmin-dumping-attack)
  - [Key Concepts](#key-concepts)
  - [Steps for the Attack](#steps-for-the-attack)
    - [1. Check for Existing Shadow Copies](#1-check-for-existing-shadow-copies)
    - [2. Create a New Shadow Copy (if none exist)](#2-create-a-new-shadow-copy-if-none-exist)
    - [3. Locate the Shadow Copy](#3-locate-the-shadow-copy)
    - [4. Copy Data from the Shadow Copy](#4-copy-data-from-the-shadow-copy)
    - [5. Extract Sensitive Data](#5-extract-sensitive-data)
  - [Execution Example](#execution-example)
  - [Why This Attack Is Dangerous](#why-this-attack-is-dangerous)