---
title: 'Exploiting SQL Server TRUSTWORTHY Property: From Database Access to sysadmin'
published: 2025-04-22
description: 'Deep dive into TRUSTWORTHY property exploitation, demonstrating how attackers leverage this setting for privilege escalation and full database server compromise'
image: ''
tags: [ Windows PrivEsc]
category: 'Privilege Escalation'
draft: false 
lang: 'ar-eng'
---

# Understanding the TRUSTWORTHY Property in SQL Server

## Table of Contents
- [Why is TRUSTWORTHY Dangerous?](#why-is-trustworthy-dangerous)
- [Exploit Scenario: Step-by-Step Breakdown](#exploit-scenario-step-by-step-breakdown)
  - [Step 1: Check the TRUSTWORTHY Property](#step-1-check-the-trustworthy-property)
  - [Step 2: Enable TRUSTWORTHY (If Not Already Enabled)](#step-2-enable-trustworthy-if-not-already-enabled)
  - [Step 3: Create a Privilege Escalation Stored Procedure](#step-3-create-a-privilege-escalation-stored-procedure)
  - [Step 4: Execute the Privilege Escalation Stored Procedure](#step-4-execute-the-privilege-escalation-stored-procedure)
  - [Step 5: Verify the Privilege Escalation](#step-5-verify-the-privilege-escalation)
- [Advanced Exploitation](#advanced-exploitation)
  - [Using CLR Assemblies for Privilege Escalation](#using-clr-assemblies-for-privilege-escalation)
- [Summary of Exploitation Steps](#summary-of-exploitation-steps)

---

The **TRUSTWORTHY** property in SQL Server is a security setting that determines whether a database is considered "trusted" by SQL Server. When **TRUSTWORTHY** is set to `ON`, SQL Server grants the database the ability to execute certain actions with the privileges of the database owner (DBO). This includes running **CLR (Common Language Runtime) assemblies** and accessing server-level resources that are usually restricted.

### Why is TRUSTWORTHY Dangerous?

When **TRUSTWORTHY** is enabled, SQL Server allows the execution of potentially dangerous operations that could elevate the privileges of an attacker. This is because:

1. **CLR Assemblies**: These can be used to run external code, and if **TRUSTWORTHY** is enabled, CLR assemblies can execute with the privileges of the database owner. An attacker can use this to run malicious code on the server.
2. **Stored Procedures**: The ability to create stored procedures with `EXECUTE AS OWNER` means that an attacker can escalate their privileges by creating and executing code that runs with the DBO’s privileges.
3. **Access to Server Resources**: Enabling **TRUSTWORTHY** also allows certain server-level operations to be performed from within the database, which would otherwise be restricted.

---

### Exploit Scenario: Step-by-Step Breakdown

#### Step 1: Check the TRUSTWORTHY Property

To determine whether the **TRUSTWORTHY** property is enabled, an attacker can query the `sys.databases` system catalog view:

```sql
SELECT name, is_trustworthy_on
FROM sys.databases
WHERE name = 'YourDatabaseName';
```

- `is_trustworthy_on = 1` means the property is enabled.
- `is_trustworthy_on = 0` means the property is disabled.

#### Step 2: Enable TRUSTWORTHY (If Not Already Enabled)

If the **TRUSTWORTHY** property is not enabled, and the attacker has sufficient privileges (such as `db_owner`), they can enable it:

```sql
ALTER DATABASE [YourDatabaseName] SET TRUSTWORTHY ON;
```

Once enabled, this allows the database to execute code with the privileges of the database owner, which could include elevated system privileges.

#### Step 3: Create a Privilege Escalation Stored Procedure

Next, the attacker can create a stored procedure that escalates their privileges. The key here is using the `EXECUTE AS OWNER` clause, which makes the stored procedure execute with the privileges of the database owner (DBO).

Here’s an example stored procedure that adds a user to the `sysadmin` server role:

```sql
CREATE PROCEDURE dbo.EscalatePrivilege
WITH EXECUTE AS OWNER
AS
BEGIN
    EXEC sp_addsrvrolemember 'attacker_username', 'sysadmin';
END;
```

- `EXECUTE AS OWNER` ensures that the stored procedure runs with the DBO's privileges, which is crucial for privilege escalation.
- `sp_addsrvrolemember` is a system stored procedure that adds a user to a server-level role, in this case, `sysadmin`.

#### Step 4: Execute the Privilege Escalation Stored Procedure

Once the procedure is created, the attacker can execute it:

```sql
EXEC dbo.EscalatePrivilege;
```

This will add the attacker’s username to the `sysadmin` role, effectively granting them full administrative privileges over the SQL Server instance.

#### Step 5: Verify the Privilege Escalation

To verify that the attacker has successfully escalated their privileges, they can check if their user is now part of the `sysadmin` role:

```sql
SELECT name
FROM sys.server_principals
WHERE is_srvrolemember('sysadmin') = 1;
```

This will return a list of users who are members of the `sysadmin` role. If the attacker’s username is listed, they have successfully escalated their privileges.

---

### Advanced Exploitation

#### Using CLR Assemblies for Privilege Escalation

In addition to stored procedures, attackers can exploit **CLR assemblies** to escalate privileges. CLR assemblies are .NET code modules that can be executed inside SQL Server. When **TRUSTWORTHY** is enabled, attackers can load and execute arbitrary CLR code with the privileges of the database owner.

1. **Create a Malicious CLR Assembly**: The attacker can create a malicious CLR assembly that performs actions like adding a user to the `sysadmin` role or executing system commands.
2. **Load the CLR Assembly into SQL Server**: After compiling the CLR code, the attacker can load it into SQL Server using the following commands:

```sql
CREATE ASSEMBLY MaliciousAssembly
FROM 'C:\Path\To\MaliciousAssembly.dll'
WITH PERMISSION_SET = UNSAFE;
```

3. **Execute the Malicious Code**: Once the assembly is loaded, the attacker can execute it from SQL Server, which will run with the privileges of the database owner.

---

### Summary of Exploitation Steps

1. **Check the TRUSTWORTHY property**: Ensure it is enabled.
2. **Enable TRUSTWORTHY** (if not already enabled) using `ALTER DATABASE`.
3. **Create a stored procedure** with `EXECUTE AS OWNER` to escalate privileges.
4. **Execute the stored procedure** to add the attacker to the `sysadmin` role.
5. **Verify privilege escalation** by checking the `sysadmin` role membership.
```

