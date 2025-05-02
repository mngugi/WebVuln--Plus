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
