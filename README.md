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



