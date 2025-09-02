# SQL Injection 5

- **Platform:** picoCTF 2025
- **Category:** Web Exploitation
- **Points:** (to be updated)

---

## 📝 Challenge Description

> The login form is vulnerable to advanced SQL Injection. Simple payloads are blocked, requiring a UNION-based injection to extract information.

---

## 🛠️ My Methodology

### 1. Initial Reconnaissance
I tested the input form and confirmed that basic bypass payloads were filtered. However, `UNION SELECT` statements were still possible.

### 2. Database Version Enumeration
To confirm the injection and identify the database type, I used a payload to extract the version.
```sql
' UNION SELECT 1, sqlite_version(), 3 --
````

This confirmed the backend was using SQLite.

### 3\. Exploitation

Knowing it was SQLite, I used `sqlite_master` to enumerate tables. I found a `users` table and then crafted a final payload to extract the `username` and `password` columns, which contained the flag.

```sql
' UNION SELECT 1, username, password FROM users --
```

-----

## 🏁 The Solution

By using a UNION-based SQL Injection tailored for SQLite, I successfully enumerated the database and extracted the flag from the user table.

**Flag:** `picoCTF{SQLi_advanced_payloads_mastered}`
