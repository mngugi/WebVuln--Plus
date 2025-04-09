# Welcome to the WebVuln- wiki!

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


***

## WEBVULN-002: Cross-Site Scripting (XSS)

### 🗂️ Category
Injection

### ⚠️ Vulnerability Overview
Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into content served to other users. It can lead to session hijacking, defacement, or redirection to malicious sites.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A search field reflects input directly back into the HTML without sanitization:

```html
<p>You searched for: <?php echo $_GET['q']; ?></p>

```
### ✅ Result
The script executes in the user's browser, demonstrating a reflected XSS.

---

### 🧪 Test Environment

- [DVWA](http://www.dvwa.co.uk/)
- [bWAPP](http://www.itsecgames.com/)
- [XSS Game by Google](https://xss-game.appspot.com/)

---

### 🔒 Mitigation

- Escape output using appropriate HTML entity encoding
- Use Content Security Policy (CSP)
- Sanitize input on the server and client side
- Prefer safe frameworks that auto-sanitize (e.g., React, Angular)
- Avoid `innerHTML`, `document.write`, and inline event handlers

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite**
- **OWASP ZAP**
- **XSS Hunter** (for stored XSS tracking)
- Manual payloads:
  ```html
  <img src=x onerror=alert(1)>
  <svg/onload=alert(1)>

***

## WEBVULN-003: Cross-Site Request Forgery (CSRF)

### 🗂️ Category
Broken Authentication / Session Management

### ⚠️ Vulnerability Overview
Cross-Site Request Forgery (CSRF) tricks a logged-in user into executing unwanted actions on a web application where they’re authenticated. Exploits rely on the user's browser automatically including session cookies.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A vulnerable banking app allows fund transfers via a simple GET request:

`http://vulnerable-bank.com/transfer?amount=1000&to=attacker_account`


If the user is authenticated, this request will succeed.

**Attack Example:**  
An attacker can embed this into an image or hidden form on a malicious website:

```html
<img src="http://vulnerable-bank.com/transfer?amount=1000&to=attacker_account">

```
### Result:


If a logged-in user visits the attacker’s page, the browser sends the request with session cookies — and funds get transferred without the user’s knowledge.

***

### 🧪 Test Environment

- [DVWA](http://www.dvwa.co.uk/)
- [bWAPP](http://www.itsecgames.com/)
- [WebGoat](https://owasp.org/www-project-webgoat/)

---

### 🔒 Mitigation

- Use anti-CSRF tokens (e.g., synchronizer tokens, double submit cookies)
- Validate `Origin` and `Referer` headers
- Use the `SameSite` cookie attribute (`SameSite=Lax` or `SameSite=Strict`)
- Require re-authentication or CAPTCHA for sensitive operations
- Avoid using GET for state-changing actions

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite Pro** (includes CSRF PoC generator)
- **OWASP ZAP**
- Manual testing using crafted HTML forms or `curl`
- Check for missing CSRF tokens in sensitive POST requests

---

### 📚 References

- [OWASP CSRF Page](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger CSRF Guide](https://portswigger.net/web-security/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)


***
## WEBVULN-004: Remote Code Execution (RCE)

### 🗂️ Category
Injection / Critical

### ⚠️ Vulnerability Overview
Remote Code Execution (RCE) allows an attacker to execute arbitrary system-level code on the target server. This is one of the most dangerous vulnerabilities, often leading to full system compromise, lateral movement, and persistence.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A web application allows users to ping a host:

```php
<?php
$host = $_GET['host'];
echo shell_exec("ping -c 1 " . $host);
?>

```
---
**Malicious Input:**


`127.0.0.1; whoami`

**Result:**

The command runs ping, then executes whoami, returning the server's current user.

**Alternative PoC Payloads:**

Linux:

`127.0.0.1; ls /`

Windows:

`127.0.0.1 & dir`

---

### 🧪 Test Environment

- [DVWA](http://www.dvwa.co.uk/)
- [bWAPP](http://www.itsecgames.com/)
- [Vulhub – RCE Labs](https://github.com/vulhub/vulhub)

---

### 🔒 Mitigation

- Never pass user input directly to system calls or `eval()` functions
- Use allowlists to strictly validate and sanitize inputs
- Avoid dangerous functions: `eval()`, `exec()`, `shell_exec()`, `popen()`, etc.
- Run applications with least privileges (non-root where possible)
- Use Web Application Firewalls (WAFs) for added detection and protection

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite Intruder**
- **Metasploit Framework**
- **Commix** (for command injection automation)
- Manual fuzzing with OS-specific payloads
- Monitor logs and output for signs of command execution

---

### 📚 References

- [OWASP RCE Guide](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger RCE](https://portswigger.net/web-security/os-command-injection)
- [GTFOBins](https://gtfobins.github.io/) — post-exploitation techniques


***
## WEBVULN-005: Command Injection

### 🗂️ Category
Injection

### ⚠️ Vulnerability Overview
Command Injection occurs when user input is passed directly to a system shell or command interpreter without proper sanitization. This allows attackers to execute arbitrary commands on the host system, potentially leading to full server compromise.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A web app provides a functionality to check server reachability:

```php
<?php
$ip = $_GET['ip'];
echo shell_exec("ping -c 1 " . $ip);
?>

```

**Malicious Input:**

`127.0.0.1; uname -a`

**Result:**

- Executes ping, then `uname -a`, leaking system info.

**PoC Payloads:**

**Linux:**

```
127.0.0.1; id
127.0.0.1 && cat /etc/passwd
```
**Windows:**

```
127.0.0.1 & whoami
127.0.0.1 | dir
```

***
### 🧪 Test Environment

- [DVWA](http://www.dvwa.co.uk/)
- [bWAPP](http://www.itsecgames.com/)
- [Vulhub – Command Injection Labs](https://github.com/vulhub/vulhub/tree/master/command-injection)

---

### 🔒 Mitigation

- Avoid executing system commands with user input
- Use safe APIs that don’t involve shell invocation
- Implement strict input validation and allowlists
- Escape shell metacharacters if shell execution is unavoidable
- Apply least privilege principles on server processes

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite Repeater/Intruder**
- **Commix** (automated command injection)
- **Metasploit Framework**
- Manual testing with OS-specific payloads
- Monitor system command logs and anomalies

---

### 📚 References

- [OWASP Command Injection Guide](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger Command Injection](https://portswigger.net/web-security/os-command-injection)
- [GTFOBins](https://gtfobins.github.io/) — for command abuse post-exploitation



***

## WEBVULN-006: Insecure Direct Object Reference (IDOR)

### 🗂️ Category
Broken Access Control

### ⚠️ Vulnerability Overview
IDOR occurs when an application exposes internal object references (like IDs, filenames, or usernames) without proper access control checks. Attackers can manipulate these references to access unauthorized data or functions.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A user profile is accessed via:

---
`GET /profile?user_id=1001`



- Changing the `user_id` to another value (e.g., `1002`) reveals another user's profile:

`GET /profile?user_id=1002`


**Result:**  
Sensitive information is disclosed due to missing authorization checks.

---

### 🧪 Test Environment

- [DVWA](http://www.dvwa.co.uk/)
- [bWAPP](http://www.itsecgames.com/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

---

### 🔒 Mitigation

- Enforce access control checks server-side for every resource
- Do not expose predictable object references (use UUIDs or indirect mapping)
- Avoid relying on client-side authorization
- Log and monitor unauthorized access attempts

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite** (manual ID tampering)
- **Postman** or custom scripts for API fuzzing
- Review server logs for abnormal ID access patterns
- Automated tools (e.g., **Autorize** Burp plugin)

---

### 📚 References

- [OWASP IDOR Guide](https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference)
- [PortSwigger IDOR](https://portswigger.net/web-security/access-control/idor)
- [OWASP Top 10: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---
## WEBVULN-007: XML Injection

### 🗂️ Category
Injection

### ⚠️ Vulnerability Overview
XML Injection occurs when user input is inserted into an XML document or query without proper sanitization. This can lead to data manipulation, authentication bypass, or even denial of service. It’s commonly seen in SOAP-based services or applications parsing XML.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A login system accepts XML-based input:

```xml
<user>
    <username>admin</username>
    <password>admin</password>
</user>

```
---

Result:
The attacker bypasses authentication if the XML is used in backend XPath or SQL queries without sanitization.

Other Payloads:

```xml

<user><name>John</name><role>admin</role></user>

```
- Insert additional nodes
- Modify structure of parsed XML
- Exploit backend processing logic

---

### 🧪 Test Environment

- [bWAPP](http://www.itsecgames.com/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- Custom SOAP/XML-based test APIs

---

### 🔒 Mitigation

- Always sanitize and encode user input before inserting into XML
- Use secure XML parsers with entity resolution disabled
- Apply schema validation (XSD) for expected structure
- Avoid string concatenation when building XML
- Enable logging and anomaly detection for malformed XML inputs

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite** (modify XML requests)
- **SOAPUI** for testing SOAP/XML APIs
- Manual injection with crafted XML payloads
- Look for unauthenticated access, malformed parsing, or logic bypass

---

### 📚 References

- [OWASP XML Injection Guide](https://owasp.org/www-community/attacks/XML_Injection)
- [PortSwigger XML Injection](https://portswigger.net/web-security/xml-injection)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---
## WEBVULN-008: LDAP Injection

### 🗂️ Category
Injection

### ⚠️ Vulnerability Overview
LDAP Injection occurs when untrusted user input is embedded into an LDAP query without proper sanitization. Attackers can manipulate LDAP filters to bypass authentication, escalate privileges, or extract sensitive directory data.

---

### 🧪 Demo / Proof of Concept

**Scenario:**  
A login form uses LDAP to authenticate:

```java
String ldapFilter = "(uid=" + user + ")";
```
**Malicious Input:**

```
Username: *)(uid=*

```

**Result:**
- LDAP filter becomes:

```
(uid=*)(uid=*)

```
- This can match all users and allow login bypass or unauthorized access.

**Other Payloads:**

- Authentication Bypass:

```
admin*)(userPassword=*
Privilege Escalation:
```
```
*)(|(admin=*))(
```
---
### 🧪 Test Environment

- [bWAPP](http://www.itsecgames.com/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- Custom apps with OpenLDAP backend

---

### 🔒 Mitigation

- Sanitize and validate all user input before including it in LDAP queries
- Use parameterized LDAP queries (e.g., with JNDI, .NET DirectoryServices)
- Apply allowlists for input fields (e.g., usernames, emails)
- Escape special characters in LDAP queries: `()|&!*=\<>~`

---

### 🛠️ Testing Tools / Techniques

- **Burp Suite**
- Manual testing with crafted LDAP filter payloads
- Inspect backend logs for suspicious filter manipulation
- Use fuzzing to detect filter anomalies

---

### 📚 References

- [OWASP LDAP Injection Guide](https://owasp.org/www-community/attacks/LDAP_Injection)
- [PortSwigger LDAP Injection](https://portswigger.net/web-security/ldap-injection)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


***
## 🛡️ Web Vulnerability Entry: XPath Injection

- **Category:** Injection  
- **Vulnerability ID:** WEBVULN-009  
- **Name:** XPath Injection  

---

### 🔍 Description
**XPath Injection** occurs when user-controlled input is unsafely embedded into XPath queries used to retrieve or manipulate data from XML documents. This allows attackers to alter the structure of the query, potentially bypassing authentication, accessing unauthorized data, or triggering denial of service.

---

### 🧪 Example / Proof of Concept

#### Vulnerable Code (PHP Example):
```php
$username = $_POST['username'];
$password = $_POST['password'];

$xml = simplexml_load_file('users.xml');
$result = $xml->xpath("//user[username/text()='$username' and password/text()='$password']");
```
---

**Attack Payload:**
```
Username: ' or '1'='1
Password: ' or '1'='1

```
**Resulting XPath:**
```
//user[username/text()='' or '1'='1' and password/text()='' or '1'='1']

```
- This always evaluates to true, allowing an attacker to bypass authentication.

### 🛡️ Mitigation

- **Input Validation & Escaping**: Always sanitize and escape user input to avoid breaking out of query structure.
- **Parameterized Queries**: Use libraries that support parameterized XPath expressions to prevent injection.
- **Avoid XML for Authentication**: Prefer secure, database-backed authentication systems where possible.
- **Least Privilege**: Ensure XML files and applications accessing them follow the principle of least privilege.

---

### 🧰 Testing Tools / Techniques

- **Manual Testing**: Try injecting XPath payloads into fields used in XML queries.
- **Burp Suite**: Intercept and modify XML requests.
- **OWASP ZAP**: Scan for XML/XPath injection points.
- **FuzzDB**: Use known XPath injection payloads for fuzzing.

---

### 📚 References

- [OWASP: XML External Entity (XXE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger: XPath Injection](https://portswigger.net/web-security/xpath-injection)


