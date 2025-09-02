# Auth Bypass

- **Platform:** picoCTF 2025
- **Category:** Web Exploitation
- **Points:** (to be updated)

---

## 📝 Challenge Description

> We are presented with a login portal that requires valid credentials. The goal is to bypass authentication and access the protected area to obtain the flag.

---

## 🛠️ My Methodology

### 1. Initial Reconnaissance
My first step was to open the challenge URL and inspect the login form. I tested it with standard credentials like `test:test`, which failed as expected.

### 2. Identifying Potential Attack Vectors
I identified the most likely vulnerabilities for an authentication bypass challenge:
- SQL Injection (`' OR '1'='1`)
- Hardcoded or default credentials (`admin:admin`)
- Cookie or session tampering (`isAdmin=false`)
- Client-side validation flaws (credentials in JS/HTML)

### 3. Exploitation
I focused on SQL Injection first. I used the classic payload `' OR '1'='1` in the username field with a random password. This is designed to make the SQL query's `WHERE` clause always evaluate to true, thus bypassing the password check.

```sql
-- Assumed backend query:
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything';
````

This payload successfully bypassed the authentication.

-----

## 🏁 The Solution

The vulnerability was a classic SQL Injection in the login form's username parameter. After bypassing the login, the flag was displayed on the resulting page.

**Flag:** `picoCTF{<insert_flag_here>}`








