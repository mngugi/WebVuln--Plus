# WebVuln-
This is a 100 Web Vulnerabilities Project.

Welcome to the WebVuln- wiki!

### WebVuln-001

Category:
* Injection

Vulnerability ID:
WEBVULN-001

* Demo/PoC:
* Scenario:
A login form with this SQL query behind it:

```sql

SELECT * FROM users WHERE username = '$username' AND password = '$password';

```

### Payload:
Enter this in the username field:

```sql

' OR '1'='1
```
Password can be anything. Result? Bypasses authentication.

PoC URL (if available):
You could simulate this using 

`DVWA, bWAPP, or WebGoat.`

### Mitigation:

> Use prepared statements / parameterized queries (e.g., with mysqli or PDO in PHP)

> Employ ORM frameworks that escape inputs automatically

> Whitelist input and validate strictly

> Disable detailed SQL error messages in production

Testing Tools/Techniques:

* sqlmap

* Burp Suite (Community/Pro)

* Manual testing with payloads

* OWASP ZAP

### References:

* OWASP SQLi Page

* PortSwigger SQLi

* OWASP Cheat Sheet: SQL Injection Prevention

