# 🎯 FDJ Bounty Recon - Quick Reference

## Files Modified

| File | Changes |
|------|---------|
| `requirements.txt` | Added: `playwright`, `rich` |
| `parser.py` | Added: `parse_forms_and_params()` function |
| `reporting.py` | Enhanced: forms, GET params, XHR endpoints sections |
| `netbear_crawler.py` | Major: BFS depth crawling, scope validation, rate limiting, stats |
| `targets.txt` | Updated: FDJ program URLs (primary & secondary) |
| `scopes.txt` | **NEW**: 100+ approved FDJ domains |
| `BOUNTY_SETUP.md` | **NEW**: Full setup guide |

---

## 🚀 One-Command Start

```powershell
cd C:\Users\Agya\BOOLEAN\Netbear
python netbear_crawler.py
```

---

## 📊 What You Get

### Per-Domain Report (e.g., `www_unibet_com/report.txt`):
```
✅ Forms discovered        (actions, methods, inputs)
✅ GET parameters         (potential IDOR: id, userId, etc.)
✅ XHR/API endpoints      (test in Burp)
✅ Internal links         (manual testing targets)
✅ Red flags detected     (captcha, anti-bot, etc.)
✅ JS analysis            (suspicious code patterns)
```

### Session Summary (`CRAWL_SUMMARY.txt`):
```
Total pages crawled: 42
Forms discovered: 18
Unique GET params: 34
XHR endpoints captured: 12
Next steps: Sort by endpoint type, test IDOR, auth bypass
```

---

## 🎯 Vuln Priorities (by reward)

| Vuln Type | Primary Target | Reward | Test Method |
|-----------|---|---|---|
| **IDOR** | Account, Profile, Payment | €5-15k | Burp: Change `userId` param |
| **Auth Bypass** | Payment, Bet Slip | €2.5-15k | Bypass session token |
| **Logic Flaw** | Betting flow, Promotions | €2.5-5k | Race conditions, state confusion |
| **XSS** | Params, Messages | €150-2.5k | Burp: Inject `<script>` in GET params |
| **Open Redirect** | Post-login, Callbacks | €150-500 | Test redirect params |
| **CSRF** | Forms (no token) | €150-2.5k | Test cross-site form submission |

---

## 🔍 How to Hunt

### Step 1: Run Crawler
```
python netbear_crawler.py
```

### Step 2: Review Reports
- Open `reports/run_YYYYMMDD_HHMMSS/CRAWL_SUMMARY.txt`
- Identify high-value endpoints (payment, account, profile)

### Step 3: Open in Burp
- Import captured XHR URLs
- Focus on GET params: `?id=`, `?userId=`, `?betId=`
- Test with different IDs (IDOR)

### Step 4: Manual Payload Testing
```
Original: https://api.unibet.com/account/profile?userId=12345
Modified: https://api.unibet.com/account/profile?userId=99999  ← Try other IDs
```

### Step 5: Document & Report
- Screenshot + request/response
- Write clear PoC steps
- Mention impact (data exposure, account takeover, payment fraud)
- Submit to YesWeHack

---

## ⚙️ Tuning

### Want Deeper Crawl?
Edit `netbear_crawler.py` line ~180:
```python
max_depth=2              # Change to 3 for 3 levels deep
max_pages_per_domain=15  # Change to 20 for more pages
```

### Want Faster?
```python
delay_sec=1.5           # Reduce to 1.0 for faster (risky)
```

### Want Proxy Rotation?
Edit `config.py`:
```python
PROXIES = [
    "http://proxy1:8080",
    "http://proxy2:8080",
]
```

---

## ✅ Scope Verification

Before testing, check if domain is in scope:
```powershell
# List all approved domains:
Get-Content scopes.txt | findstr /V "^#"
```

**If domain missing:** Add to `scopes.txt` and restart

---

## ⚠️ Golden Rules

✅ **DO:**
- Map endpoints (no payloads)
- Test with test accounts
- Write clear PoCs
- Document everything

❌ **DON'T:**
- Inject payloads during crawl
- Access real user data
- Cause DoS
- Scan outside approved scope
- Automate large-scale testing

---

## 📈 Success Metrics

**Good crawl results:**
- ✅ 10+ forms found
- ✅ 5+ GET params discovered
- ✅ 8+ XHR endpoints captured
- ✅ 50+ internal links mapped
- ✅ 0 out-of-scope warnings

**Next phase:**
- Test top 5 IDOR candidates
- Attempt auth bypass on payment
- Check for logic flaws in betting flow

---

## 🆘 Common Issues

| Issue | Fix |
|-------|-----|
| "Not in scope" error | Add domain to `scopes.txt` |
| Crawler freezes | Increase `TIMEOUT` in `config.py` |
| No forms found | Check screenshot—page may not have loaded |
| Network errors | Disable proxy, check internet |
| Very slow crawl | Reduce `max_pages_per_domain` or increase `delay_sec` |

---

## 📞 Support

See `BOUNTY_SETUP.md` for detailed docs and troubleshooting.

---

**Ready?** Run: `python netbear_crawler.py` 🚀
