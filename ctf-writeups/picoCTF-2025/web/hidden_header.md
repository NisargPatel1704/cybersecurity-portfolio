# Hidden Header

- **Platform:** picoCTF 2025
- **Category:** Web Exploitation
- **Points:** (to be updated)

---

## 📝 Challenge Description

> The website shows a "403 Forbidden" message. The challenge is to access the page by sending a request with a specific, non-standard HTTP header.

---

## 🛠️ My Methodology

### 1. Initial Reconnaissance
Browsing to the URL resulted in a `403 Forbidden` error. I checked the page's source code and found a comment that hinted at a required header: `X-Access-Key`.

### 2. Exploitation
I used `curl` to craft a new HTTP request that included the required custom header `X-Access-Key` with a likely value.

```bash
curl -H "X-Access-Key: letmein" [http://challenge-site.com/hidden](http://challenge-site.com/hidden)
````

-----

## 🏁 The Solution

The server responded to the crafted `curl` request with the page content, which included the flag.

**Flag:** `picoCTF{headers_are_fun}`