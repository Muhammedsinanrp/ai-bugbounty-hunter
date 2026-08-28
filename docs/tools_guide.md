# 🛠 Tools Installation Guide

## Install All Tools (Linux — One Script)

```bash
#!/bin/bash
# Install all bug bounty tools on Ubuntu/Debian/Kali

echo "[*] Installing Go..."
wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
rm go1.22.0.linux-amd64.tar.gz

echo "[*] Installing ProjectDiscovery tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest

echo "[*] Installing recon tools..."
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
go install github.com/sensepost/gowitness@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/ffuf/ffuf/v2@latest

echo "[*] Installing vuln scanners..."
go install github.com/hahwul/dalfox/v2@latest
pip3 install sqlmap --quiet

echo "[*] Installing amass..."
go install github.com/owasp-amass/amass/v4/...@master

echo "[*] Updating Nuclei templates..."
nuclei -update-templates

echo "[*] Downloading SecLists wordlists..."
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/.local/share/wordlists/SecLists

echo "[+] All tools installed!"
echo ""
echo "Verify:"
subfinder -version
httpx -version
nuclei -version
katana -version
dalfox version
```

---

## Tool Quick Reference

### Subdomain Enumeration

```bash
# subfinder — fast passive
subfinder -d target.com -all -silent
subfinder -d target.com -all -silent -o subs.txt

# amass — comprehensive
amass enum -passive -d target.com
amass enum -active -d target.com -brute  # slower, more thorough

# dnsx — DNS resolution + bruteforce
dnsx -d target.com -w wordlists/subdomains.txt -silent
cat subs.txt | dnsx -silent

# Online (no install)
curl "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Live Host Probing

```bash
# httpx — comprehensive
cat subs.txt | httpx -silent -status-code -title -tech-detect -cdn -ip

# httpx — just URLs
cat subs.txt | httpx -silent > live.txt

# Filter by status
cat subs.txt | httpx -silent -mc 200,301,302
```

### URL Discovery

```bash
# katana — smart crawler
katana -u https://target.com -d 5 -silent
katana -list urls.txt -d 3 -silent -o all_urls.txt
katana -u https://target.com -jc -silent  # JS crawling

# Wayback Machine
echo "target.com" | waybackurls
echo "target.com" | gau

# Get only URLs with parameters
cat all_urls.txt | grep "="

# Get unique parameters
cat all_urls.txt | grep "=" | sed 's/=.*/=/g' | sort -u
```

### Fuzzing

```bash
# ffuf — directory brute force
ffuf -u https://target.com/FUZZ \
  -w ~/.local/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,403 \
  -fc 404 \
  -t 50

# ffuf — parameter fuzzing
ffuf -u https://target.com/api/FUZZ \
  -w ~/.local/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200

# ffuf — POST body fuzzing
ffuf -u https://target.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -w passwords.txt \
  -mc 302
```

### XSS

```bash
# dalfox — automated XSS
dalfox url "https://target.com/search?q=test"
dalfox url "https://target.com/search?q=test" -b your-burp-collaborator.com
cat params.txt | dalfox pipe -b your-oast.com

# kxss — quick detection
echo "https://target.com/search?q=FUZZ" | kxss
cat params.txt | qsreplace '"><svg onload=alert(1)>' | kxss
```

### SQL Injection

```bash
# sqlmap — automated
sqlmap -u "https://target.com/item?id=1" --dbs --batch
sqlmap -u "https://target.com/login" \
  --data="user=admin&pass=test" \
  --level=5 --risk=3 \
  --dbs --tables --dump

# sqlmap — with cookie
sqlmap -u "https://target.com/profile?id=1" \
  --cookie="session=abc123" \
  --dbs

# sqlmap — batch file
sqlmap -m urls.txt --dbs --batch
```

### Template-based Scanning (Nuclei)

```bash
# Run all templates
nuclei -u https://target.com -t nuclei-templates/

# Specific categories
nuclei -u https://target.com -t cves/           # Known CVEs
nuclei -u https://target.com -t exposures/      # Info exposure
nuclei -u https://target.com -t misconfigurations/
nuclei -u https://target.com -t vulnerabilities/
nuclei -u https://target.com -t default-logins/ # Default creds

# Scan list of hosts
nuclei -list live.txt -t nuclei-templates/ -o findings.txt

# High severity only
nuclei -u https://target.com -severity critical,high

# Exclude info
nuclei -list live.txt -severity critical,high,medium -o results.txt
```

### Screenshots

```bash
# gowitness — screenshot all live hosts
gowitness file -f live.txt -P screenshots/
gowitness scan file -f live.txt --write-db
gowitness report serve  # View in browser at :7171
```

### OSINT

```bash
# whois
whois target.com

# DNS enumeration
dig target.com A
dig target.com MX
dig target.com TXT
dig target.com NS

# Shodan CLI
shodan search hostname:target.com
shodan host 1.2.3.4

# theHarvester
theHarvester -d target.com -l 500 -b google,bing,linkedin

# Google dorks (manual)
site:target.com filetype:env
site:github.com "target.com" password
```

---

## Burp Suite Setup

```
1. Download: https://portswigger.net/burp/communitydownload
2. Proxy → Options → Port: 8080
3. Browser: set proxy to 127.0.0.1:8080
4. Install Burp CA cert in browser
5. Key extensions to install (BApp Store):
   - Logger++         (log all requests)
   - Param Miner      (find hidden params)
   - Turbo Intruder   (fast fuzzing)
   - JWT Editor       (JWT attacks)
   - Hackvertor       (payload encoding)
   - CSRF Scanner     (auto CSRF testing)
   - Active Scan++    (extended scanner)
```

---

## Recommended Wordlists (SecLists)

```bash
# After installing SecLists:
SECLISTS=~/.local/share/wordlists/SecLists

# Directories
$SECLISTS/Discovery/Web-Content/common.txt
$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt
$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt

# API endpoints
$SECLISTS/Discovery/Web-Content/api/api-endpoints.txt

# Subdomains
$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt
$SECLISTS/Discovery/DNS/bitquark-subdomains-top100000.txt

# Parameters
$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt

# Passwords
$SECLISTS/Passwords/Common-Credentials/10k-most-common.txt

# XSS
$SECLISTS/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt

# SQLi
$SECLISTS/Fuzzing/SQLi/Generic-SQLi.txt
```
