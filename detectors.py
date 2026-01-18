# detectors.py
import re
from urllib.parse import urlparse
import tldextract

# === CAPTCHA Detection ===
def detect_captcha(html: str) -> str:
    patterns = [
        r"captcha",
        r"captchav2",
        r"cloudflare",
        r"challenge",
        r"verify  you are human",
        r"verifying you are human",
        r"checking security of your connection",
        r"please prove you are human",
        r"recaptcha",
        r"g-recaptcha",
        r"hcaptcha",
        r"cf-chl",          # Cloudflare challenge
        r"challenge-form",  # generic form markers
        r"are you human",
    ]
    if any(re.search(p, html, re.I) for p in patterns):
        return "⚠️ CAPTCHA or challenge detected"
    return "None"

# === Smarter Red Flag / Phishing Detection ===
def detect_red_flags(url: str, html: str, links: list | None = None, js_xhr_urls: list | None = None) -> dict:
    red_flags = []
    lower_html = html.lower()
    score = 0  # suspicion score

    # Extract domain for brand-domain checks
    domain = tldextract.extract(url).registered_domain

    # 1. Strong scam keywords (require context)
    scam_keywords = [
        "free money", "win big", "lottery", "claim prize", "urgent action",
        "congratulations you won", "crypto giveaway", "double your btc",
        "investment scheme", "work from home and earn"
    ]
    for kw in scam_keywords:
        if kw in lower_html:
            # Only flag if also a form or suspicious link present
            if re.search(r"<form[^>]+>", html, re.I) or (links and len(links) > 0):
                red_flags.append(f"Suspicious phrase with context: {kw}")
                score += 2

    # 2. Brand phishing (require login form and mismatch domain)
    brands = {
        "paypal": "paypal.com",
        "apple": "apple.com",
        "microsoft": "microsoft.com",
        "google": "google.com",
        "amazon": "amazon.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "bank": None,  # generic case
    }
    for brand, legit_domain in brands.items():
        if brand in lower_html and "login" in lower_html:
            # Only flag if login form present
            if re.search(r"<form[^>]+>", html, re.I):
                if not legit_domain or legit_domain not in domain.lower():
                    red_flags.append(f"Possible Login/Phishing: {brand} login form on {domain}")
                    score += 3

    # 3. Suspicious links and API endpoints
    if links:
        for link in links:
            parsed = urlparse(link)
            # Raw IP links
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or ""):
                red_flags.append(f"Suspicious link (raw IP): {link}")
                score += 2
            # Punycode / IDN
            if parsed.hostname and "xn--" in parsed.hostname:
                red_flags.append(f"Suspicious punycode domain: {parsed.hostname}")
                score += 2
            # Shady TLDs
            shady_tlds = (".zip", ".xyz", ".top", ".club", ".click", ".work", ".gq", ".ml", ".tk")
            if parsed.hostname and parsed.hostname.endswith(shady_tlds):
                red_flags.append(f"Suspicious TLD in link: {parsed.hostname}")
                score += 2
            # Suspicious API endpoints
            if "/api/" in link or "token" in link or "auth" in link:
                if not parsed.hostname or parsed.hostname not in domain:
                    red_flags.append(f"Suspicious API endpoint: {link}")
                    score += 2

    # 4. JS/XHR resource URLs (deeper analysis)
    if js_xhr_urls:
        for res_url in js_xhr_urls:
            parsed = urlparse(res_url)
            # Known phishing/malware domains (example list)
            known_bad = ["phishingsite.com", "malwaredomain.com", "badactor.net"]
            if parsed.hostname and any(bad in parsed.hostname for bad in known_bad):
                red_flags.append(f"Known malicious JS/XHR resource: {res_url}")
                score += 4
            # Suspicious parameters
            if "token" in res_url or "auth" in res_url or "sessionid" in res_url:
                if not parsed.hostname or parsed.hostname not in domain:
                    red_flags.append(f"Suspicious parameter in JS/XHR: {res_url}")
                    score += 2

    # 5. Sensitive forms (only if not on brand domain and with suspicious fields)
    if re.search(r"<form[^>]+>", html, re.I):
        if re.search(r"(password|credit card|ssn|bank|cvv)", lower_html):
            if not any(legit in domain for legit in brands.values() if legit):
                red_flags.append("Form requesting sensitive info on untrusted domain")
                score += 3

    # 6. Obfuscated JavaScript (only if other indicators present)
    obfuscated_js = False
    if "eval(" in lower_html or "atob(" in lower_html or "base64" in lower_html:
        obfuscated_js = True
    if obfuscated_js and score > 0:
        red_flags.append("Possible obfuscated JavaScript (with other suspicious indicators)")
        score += 1

    return {"flags": red_flags, "score": score}
