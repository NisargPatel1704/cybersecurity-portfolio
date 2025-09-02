# SQL Injection 4

- **Platform:** picoCTF 2025
- **Category:** Web Exploitation
- **Points:** (to be updated)

---

## 📝 Challenge Description

> The web application seems to be vulnerable to SQL injection. The goal is to exploit the vulnerability to extract the flag from the database, likely requiring a UNION-based attack.

---

## 🛠️ My Methodology

### 1. Determine Column Count
The first step in a UNION-based attack is to find the number of columns in the original query. I used the `ORDER BY` clause, incrementing the column index until I received an error.
```sql
' ORDER BY 3 --
````

This failed, telling me the query returned 2 columns.

### 2\. Find Displayed Columns & Extract Data

Next, I used a `UNION SELECT` statement to determine which of the two columns were displayed on the page. Then, I used this to extract information from the database schema.

```sql
' UNION SELECT table_name, column_name FROM information_schema.columns --
```

### 3\. Exploitation

After enumerating tables and columns, I identified a table named `flags` with a column named `flag`. I crafted the final payload to extract its content.

```sql
' UNION SELECT null, flag FROM flags --
```

-----

## 🏁 The Solution

Using a systematic UNION-based SQL Injection, I was able to enumerate the database and extract the flag directly from a `flags` table.

**Flag:** `picoCTF{...}`

````