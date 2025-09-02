# Server-Side Template Injection 1

- **Platform:** picoCTF 2025
- **Category:** Web Exploitation
- **Points:** (to be updated)

---

## 📝 Challenge Description

> A web application reflects user input back onto the page. The task is to check for and exploit a Server-Side Template Injection (SSTI) vulnerability to read the flag from the server's file system.

---

## 🛠️ My Methodology

### 1. Identifying the Vulnerability
My first step was to test if the server was processing template syntax. I submitted the payload `{{7*7}}`. The server responded with `49`, confirming that it was vulnerable to SSTI, likely using the Jinja2 template engine (common in Flask apps).

### 2. Finding an Exploitation Path
With SSTI confirmed, my goal was to find an object that would allow me to access the underlying operating system and execute commands. I used a common payload to explore the available objects.


{{ self.**init**.**globals** }}



### 3. Exploitation
From the available objects, I found the `os` module. I then crafted a final payload to use `os.popen()` to execute the `cat` command and read the `flag.txt` file.
```

{{ self.**init**.**globals**['os'].popen('cat flag.txt').read() }}

```

---

# 🏁 The Solution

By identifying and exploiting an SSTI vulnerability, I was able to achieve remote code execution on the server and read the contents of the flag file.

**Flag:** `picoCTF{<captured_flag>}`
