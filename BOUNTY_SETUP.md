# NetBear FDJ United Bug Bounty Recon Setup

## ✅ Completed Modifications

Your NetBear crawler has been upgraded for FDJ United (YesWeHack) bounty hunting. Here's what changed:

### 1. **Dependencies Updated** ✓
- `requirements.txt` now includes `playwright` and `rich`
- All packages installed in venv
- Chromium browser ready for Playwright

### 2. **Scope Management** ✓
- **New file:** `scopes.txt` with 100+ FDJ-approved domains
- Crawler validates **every URL** against scope before crawling
- Includes: unibet.*, mariacasino.*, 32red.*, bingo.com, payment.* endpoints, kindredgroup

### 3. **Enhanced Parsing** ✓
- **New function:** `parse_forms_and_params()` in `parser.py`
- Extracts: form actions/methods/inputs, GET parameters
- Filters for **IDOR candidates**: `id`, `userId`, `betId`, `accountId`, `profileId`, etc.

### 4. **Depth-Based Crawling** ✓
- **Breadth-First Search (BFS)** with configurable depth (default: 2 levels)
- Starts at home → crawls ~1-2 levels deep per domain
- **Rate limiting:** 1.5 sec between requests (respects targets)
- **Max 15 pages/domain** to avoid hammering

### 5. **Enriched Reporting** ✓
Reports now include:
- **Discovered Forms** (action, method, inputs)
- **GET Parameters** (with IDOR hints)
- **XHR/API Endpoints** (test in Burp)
- **Internal Links** (for manual testing)
- **JavaScript Analysis** (existing)
- **Crawl Summary** with stats (forms, params, links found)

### 6. **Updated Targets** ✓
- `targets.txt` now has FDJ program URLs
- Primary targets: www.unibet.com, www.mariacasino.com, payment endpoints
- Secondary: Regional unibet/mariacasino variants

---

## 🚀 Quick Start

### Run the crawler:
```bash
cd c:\Users\Agya\BOOLEAN\Netbear
python netbear_crawler.py
```

### What to expect:
1. Loads scopes from `scopes.txt` (validate domains)
2. Reads targets from `targets.txt`
3. Crawls each domain with depth=2 (home + 1 level)
4. **Respects rate limits** (1.5 sec between requests)
5. Generates reports in `reports/run_YYYYMMDD_HHMMSS/`

### Output Structure:
```
reports/run_20260112_150000/
├── CRAWL_SUMMARY.txt           ← Key findings overview
├── www_unibet_com/
│   ├── report.txt              ← Forms, params, APIs, internal links
│   ├── screenshot.png
│   ├── trace.zip               ← Network trace (if enabled)
│   ├── res_0.js, res_1.js, ... ← Captured JS
│   └── xhr_0.json, xhr_1.json  ← XHR responses
├── payment_unibet_com/
│   └── report.txt
└── ...
```

---

## 🎯 Vuln Hunting Workflow

### After crawl completes:

#### 1. **Sort Endpoints by Type**
```bash
# From reports, identify:
# - /account/, /profile/ → IDOR candidates
# - /payment/, /billing/ → Auth bypass, race conditions
# - /api/bets/, /api/odds/ → Logic flaws
```

#### 2. **Manual Testing (Burp Suite)**
- Import captured XHR endpoints from `report.txt`
- Test IDOR: Use GET params like `?userId=` with different IDs
- Check auth: Replace cookies, retry payment forms
- Look for race conditions on bet placement

#### 3. **High-Priority Patterns**
- `id=123, userId=456, betId=789` → **IDOR** (€5-15k)
- Unencrypted params (esp. payment) → **Auth Bypass** (€2.5-15k)
- Form with no CSRF token → **CSRF** (€150-2.5k)
- Unvalidated redirect → **Open Redirect** (€150-500)
- JS with secrets/API keys → **Information Disclosure** (€150-2.5k)

#### 4. **Respect Boundaries**
- ✅ DO: Map, identify endpoints, write PoCs with test accounts
- ❌ DON'T: Actual payload injection, data exfiltration, DoS
- ⚠️ Report impact: Real accounts, payment bypass, user data = max bounties

---

## ⚙️ Configuration

### Crawl Depth (in `netbear_crawler.py`):
```python
domain_results, domain_stats = crawl_domain_with_depth(
    url, 
    run_dir, 
    max_depth=2,              # ← Increase to 3 for deeper mapping
    max_pages_per_domain=15,  # ← Increase for larger sites
    delay_sec=1.5             # ← Increase to 2-3 for sensitive sites
)
```

### Enable/Disable Tracing (in `config.py`):
```python
ENABLE_TRACING = True   # Captures network traces (slower, heavier files)
```

### Proxy Support (in `config.py`):
```python
PROXIES = [
    "http://user:pass@proxy1:8080",
    "http://proxy2:8000",
    "socks5://proxy3:1080"
]
# Crawler rotates proxies per request
```

---

## 📋 FDJ Program Key Info

- **Organization:** Kindred Group (Unibet, Maria Casino, 32Red, etc.)
- **Total Scopes:** 34 (web + iOS/Android)
- **Rewards:**
  - **Critical on main assets:** €15,000
  - **High on secondary:** €2,500
  - **Lower tiers:** €150–€5,000
- **Prime Targets:** Account/profile, payments, betting flows
- **Ineligible:** Phishing sites, DDoS (this isn't relevant—focus on legit vulns)

---

## 🔍 Report Anatomy Example

```
NetBear Report
URL: https://www.unibet.com/en/casino
Domain: unibet.com
...

--- Discovered Forms ---
Form 1:
  Action: https://www.unibet.com/en/api/account/login
  Method: POST
  Inputs: username, password, remember_me, csrf_token

Form 2:
  Action: https://www.unibet.com/en/bet-slip
  Method: POST
  Inputs: betId, stake, odds, betType

--- Potential GET Parameters ---
id, userId, sessionId, betSlipId, betId
(⚠️  IDOR Candidates: id, userId, betId, accountId, playerId, profileId, etc.)

--- Captured XHR/API Endpoints ---
  https://api.unibet.com/betslip/v1/place
  https://api.unibet.com/account/profile
  https://api.unibet.com/balance
  
--- Internal Links (for manual testing) ---
  https://www.unibet.com/en/sports/
  https://www.unibet.com/en/casino/
  https://www.unibet.com/en/account/deposits/
  ...
```

---

## ⚠️ Important Notes

1. **Respect Scope:** Only test domains in `scopes.txt`
2. **No Active Injection:** Crawler maps only; you test manually
3. **Rate Limits:** 1.5 sec default is generous—don't override
4. **No DoS/Automation at Scale:** Stay under radar; use for recon
5. **Document Everything:** Screenshot PoC, save requests, write clear reports

---

## Troubleshooting

### Crawler hangs at Chromium startup?
- Playwright may need more time; check `TIMEOUT` in `config.py` (default 60s)

### "Not in scope" warnings?
- Verify domain in `scopes.txt`; add if missing

### No forms/params found?
- Site may be heavily JS-rendered; check `screenshot.png` to verify page loaded

### Network errors?
- Proxy issues? Check `PROXIES` list; disable if unreliable

---

## Next Steps

1. **Run crawler** on primary targets (unibet.com, mariacasino.com)
2. **Review reports** for high-value endpoints
3. **Manual test** with Burp:
   - IDOR on account/profile (high impact)
   - Auth bypass on payments (critical)
   - Logic flaws in betting flows
4. **Build PoCs** for reportable vulns
5. **Submit to YesWeHack** with clear steps + impact

Good luck! 🎯

---

**Last Updated:** Jan 12, 2026  
**Crawler Version:** NetBear v2 (Bounty Mode)  
**Program:** FDJ United / Kindred Group (YesWeHack)
