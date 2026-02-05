# Web Exploitation Tools (03_web)

CTF web security toolkit for requests, CSRF, file uploads, SSTI, LFI, JWT attacks.

## Quick Start

### Setup

```bash
# Activate environment
source .venv/bin/activate
# or
uv venv && source .venv/bin/activate

# Install dependencies (if needed)
uv pip install requests beautifulsoup4 pycryptodome
```

### Download Wordlists

```bash
# From SecLists (rockyou.txt)
cd 03_web/wordlists/SecLists
tar -xzf Passwords/Leaked-Databases/rockyou.txt.tar.gz

# Also available in payloads/ for quick reference
```

## Scripts

### `web_requests.py` (Template)
Basic template with `requests.Session()`, CSRF extraction, proxy support.
- Use as starting point for custom web challenges
- Includes login, file upload, SQL injection patterns

### `csrf_grabber.py`
Auto-extract and use CSRF tokens from forms.
```bash
python csrf_grabber.py <target_url> <form_action>
```
- Extracts CSRF token from form
- Automatically includes in POST requests
- Useful for CSRF-protected forms

### `lfi_tester.py`
Test Local File Inclusion (LFI) vulnerabilities.
```bash
python lfi_tester.py <target_url> <parameter_name>
```
- Tests common LFI payloads (/etc/passwd, /proc/self/environ, etc.)
- Detects successful inclusion attempts
- Uses filter bypass techniques (encoding, wrappers)

### `ssti_tester.py`
Test Server-Side Template Injection (SSTI) vulnerabilities.
```bash
python ssti_tester.py <target_url> <parameter_name>
```
- Tests Jinja2, Mako, Jinja, ERB templates
- Math expressions to detect SSTI
- Includes payload examples for exploitation

### `upload_tester.py`
Test file upload vulnerabilities.
```bash
python upload_tester.py <target_url> <upload_endpoint>
```
- Tests extension filtering bypass (double extension, case variation, null bytes)
- MIME type bypass attempts
- Polyglot file creation (valid image + PHP/shell)

### `jwt_tamper.py`
Tamper with JWT tokens.
```bash
python jwt_tamper.py <jwt_token> [new_payload]
```
- Decode JWT (header.payload.signature)
- Modify claims (aud, sub, exp, etc.)
- Test signature bypass (none algorithm, key confusion)
- Encode tampered token

## Usage Examples

### CSRF Form Bypass
```bash
python csrf_grabber.py http://target.com/admin http://target.com/admin/action
```

### LFI Testing
```bash
python lfi_tester.py http://target.com/read?file= file
```

### SSTI Detection
```bash
python ssti_tester.py http://target.com/submit name
```

### Upload Bypass
```bash
python upload_tester.py http://target.com http://target.com/upload
```

### JWT Token Manipulation
```bash
python jwt_tamper.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"
```

## Burp Suite Integration

All scripts support proxy debugging:

```python
# Uncomment in script
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
session.proxies.update(proxies)
session.verify = False
```

Or enable at runtime:
```bash
# Set environment variable
export HTTP_PROXY=http://127.0.0.1:8080
python script.py <args>
```

## Anti-Patterns

- ❌ Don't use sqlmap/dirsearch (focus on targeted testing)
- ❌ Don't create complex web frameworks (simple request patterns only)
- ❌ Don't brute-force without rate limiting (use `time.sleep()`)
- ❌ Don't ignore SSL errors in real challenges (set `verify=False` intentionally)

## Common Payloads

### LFI Filter Bypass
```
../../etc/passwd
..%2F..%2Fetc%2Fpasswd
....//....//etc/passwd
```

### SSTI Detection
```
{{ 7 * 7 }}
${7*7}
<%= 7 * 7 %>
```

### JWT Algorithm Confusion
```json
{"alg": "none", "typ": "JWT"}
```

## Dependencies

- `requests` - HTTP client
- `beautifulsoup4` - HTML parsing
- `pycryptodome` - JWT manipulation (if needed)

## References

- OWASP: https://owasp.org/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- PortSwigger: https://portswigger.net/web-security
