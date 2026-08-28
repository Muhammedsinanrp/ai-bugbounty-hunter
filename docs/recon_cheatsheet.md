# 🔍 Recon Cheat Sheet

## Quick Recon Pipeline (Copy-Paste Ready)

```bash
TARGET="example.com"

# 1. Subdomains
subfinder -d $TARGET -all -silent -o subs.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u >> subs.txt
sort -u subs.txt -o subs.txt
echo "[+] Subdomains: $(wc -l < subs.txt)"

# 2. Live hosts
cat subs.txt | httpx -silent -status-code -title -tech-detect -o live.txt
echo "[+] Live: $(wc -l < live.txt)"

# 3. URLs + parameters
katana -list live.txt -d 3 -silent -o urls.txt
waybackurls $TARGET >> urls.txt
gau $TARGET >> urls.txt
sort -u urls.txt -o urls.txt
grep "=" urls.txt > params.txt
echo "[+] URLs: $(wc -l < urls.txt) | Params: $(wc -l < params.txt)"

# 4. Directories
ffuf -u https://$TARGET/FUZZ \
  -w ~/.local/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,403 -t 50 -o dirs.json -of json

# 5. Screenshots
gowitness file -f live.txt -P screenshots/

echo "[+] Recon complete!"
```

---

## Subdomain Sources

| Source | Method |
|--------|--------|
| CRT.sh | Certificate Transparency |
| Wayback | Historical DNS |
| SecurityTrails | DNS history API |
| Shodan | IP/port scan |
| subfinder | Passive OSINT |
| amass | Active + Passive |
| dnsx | DNS bruteforce |
| AI Prediction | Pattern-based |

## Google Dorks

```
site:target.com                          All indexed pages
site:target.com filetype:pdf             PDF files
site:target.com inurl:admin              Admin panels
site:target.com inurl:login              Login pages
site:target.com inurl:api                API endpoints
site:target.com "index of"               Directory listing
site:target.com ext:env                  .env files
site:target.com ext:sql                  SQL dumps
site:target.com "DB_PASSWORD"            Database creds
site:target.com "api_key" OR "apikey"   API keys
site:github.com "target.com" "password" GitHub leaks
```

## Shodan Dorks

```
org:"Target Company"
org:"Target" port:8080
org:"Target" http.title:"Dashboard"
org:"Target" http.title:"phpMyAdmin"
hostname:target.com
ssl.cert.subject.cn:target.com
```

## Juicy Files to Find

```
/.env                   App secrets
/.git/config            Git config (code leak)
/config.json            Config
/wp-config.php          WordPress DB creds
/phpinfo.php            PHP info dump
/.htpasswd              HTTP basic auth creds
/backup.sql             Database backup
/robots.txt             Hidden paths
/sitemap.xml            All URLs
/.well-known/           ACME challenges
/swagger.json           API docs
/api-docs               API docs
/graphql                GraphQL endpoint
/admin                  Admin panel
```

## Tech Stack → Attack Map

```
PHP        → LFI, RFI, Type Juggling, Deserialization
Node.js    → Prototype Pollution, SSJI, Path Traversal  
Python     → SSTI (Jinja2), SSRF, Pickle Deserialization
Ruby/Rails → Mass Assignment, SQL Injection, CSRF
Java       → XXE, Deserialization (Java gadgets), SSTI
.NET       → Viewstate, Deserialization, SQL Injection
WordPress  → Plugin vulns, xmlrpc.php abuse
Jinja2     → SSTI {{config}}, RCE
GraphQL    → Introspection, Injection, IDOR
JWT        → Algorithm confusion, weak secret
```
