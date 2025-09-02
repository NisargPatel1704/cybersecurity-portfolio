# SQL Injection 2
Platform: picoCTF 2025

Category: Web Exploitation

Difficulty: Medium

Points: 200

# 📝 Challenge Description
Another login challenge, but this time the application may require both a valid username and password match. A simple ' OR '1'='1' might not be enough.

# 🛠️ My Methodology
# 1. Initial Reconnaissance
I tested the login form. The classic ' OR '1'='1' payload in a single field failed, which indicated that the backend query might be validating both the username and password fields separately or using stronger logic.

# 2. Identifying and Testing the Vulnerability
My next approach was to inject a true condition into both the username and password fields simultaneously. This is often effective when the backend WHERE clause checks both parameters with an AND condition.

# 3. Exploitation
I used the payload ' OR '1'='1' in both the username and password fields.

# Username: admin' OR '1'='1

# Password: ' OR '1'='1

This payload successfully bypassed the authentication check by making the condition for both fields true.

# 🏁 The Solution
Injecting a tautology into both input fields satisfied the server-side validation and granted access, revealing the flag on the dashboard.

Flag: picoCTF{<insert-flag-here>}