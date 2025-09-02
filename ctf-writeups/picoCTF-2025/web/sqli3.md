# SQL Injection 3

- **Platform:** picoCTF 2025
- **Category:** Web Exploitation
- **Difficulty:** Medium-Hard
- **Points:** 250

---

## 📝 Challenge Description

> This challenge strengthens the login form even more. The developer is likely filtering basic payloads (like `' OR '1'='1`) or blocking keywords like `UNION`. We’ll need to use filter bypass techniques.

---

## 🛠️ My Methodology

### 1. Initial Reconnaissance
I confirmed that basic payloads like `admin' OR '1'='1'--` were being blocked by a Web Application Firewall (WAF) or a backend filter.

### 2. Identifying and Testing the Vulnerability
My strategy shifted to testing filter bypass techniques. I focused on case variations and using inline comments to break up forbidden keywords.

### 3. Exploitation
I discovered that the filter was case-sensitive and did not properly handle SQL comments. I crafted a new payload that used mixed-case letters for the `OR` keyword.

-   **Username:** `admin' oR '1'='1'--`
-   **Password:** `anything`

This payload was not caught by the filter and successfully bypassed the login.

---

## 🏁 The Solution

By using case variation (`oR`) to bypass a weak filter, I was able to perform a successful SQL Injection and retrieve the flag.

**Flag:** `picoCTF{<insert_flag_here>}`
```