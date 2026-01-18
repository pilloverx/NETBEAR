# js_analyzer.py
import re
import math
import json

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum(p * math.log2(p) for p in prob)

def extract_structured_patterns(text):
    """
    Extract API endpoints, parameter names, and sensitive sinks from JS.
    Returns a dict with organized findings.
    """
    patterns = {
        "api_endpoints": [],
        "param_names": [],
        "sensitive_sinks": [],
        "auth_related": [],
        "storage_ops": [],
        "high_interest_keywords": []
    }
    
    # Extract API endpoints (fetch, axios, XMLHttpRequest patterns)
    api_patterns = [
        r"(?:fetch|axios\.(?:get|post|put|delete|patch))\(['\"]([^'\"?]+)['\"]",
        r"(?:fetch|axios\.(?:get|post|put|delete|patch))\(`([^`?]+)`",
        r"url:\s*['\"]([^'\"]+)['\"]",
        r"endpoint:\s*['\"]([^'\"]+)['\"]",
    ]
    for pattern in api_patterns:
        endpoints = re.findall(pattern, text, re.IGNORECASE)
        patterns["api_endpoints"].extend(endpoints)
    
    # Extract parameter names (common IDOR/access control targets)
    param_keywords = [
        r"(?:patient|user|doctor|specialist|appointment|booking|slot|order|id)[_-]?(?:id|Id|ID)",
        r"(?:userId|patientId|doctorId|appointmentId|bookingId|slotId|orderId)",
        r"(?:[a-z]+Id)(?=['\"],|\s|&|=|\))",
    ]
    for pattern in param_keywords:
        params = re.findall(pattern, text, re.IGNORECASE)
        patterns["param_names"].extend(params)
    
    # Sensitive sinks (XSS/code injection vectors)
    sink_patterns = [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"document\.write\(",
        r"eval\(",
        r"new\s+Function\(",
        r"setTimeout\(['\"]",
        r"setInterval\(['\"]",
    ]
    for pattern in sink_patterns:
        sinks = re.findall(pattern, text)
        if sinks:
            patterns["sensitive_sinks"].append(pattern.replace(r"\\", ""))
    
    # Auth/token handling
    auth_patterns = [
        r"(?:authorization|bearer|token|jwt|oauth|x-api-key)['\"]?\s*[:=]",
        r"(?:localStorage|sessionStorage)\.setItem\(['\"](?:token|auth|jwt)",
        r"(?:document\.cookie\s*=|cookie:\s*['\"])",
    ]
    for pattern in auth_patterns:
        auth = re.findall(pattern, text, re.IGNORECASE)
        if auth:
            patterns["auth_related"].append(pattern.replace(r"\\", ""))
    
    # Storage operations
    storage_patterns = [
        r"localStorage\.setItem\(['\"]([^'\"]+)",
        r"sessionStorage\.setItem\(['\"]([^'\"]+)",
    ]
    for pattern in storage_patterns:
        storage = re.findall(pattern, text)
        patterns["storage_ops"].extend(storage)
    
    # High-interest keywords (domain-specific for Doctolib, booking, healthcare)
    high_interest = [
        "appointment", "booking", "patient", "doctor", "specialist",
        "availability", "slot", "prescription", "medical", "healthcare",
        "idor", "csrf", "jwt", "token", "session", "auth"
    ]
    found_keywords = [kw for kw in high_interest if kw.lower() in text.lower()]
    patterns["high_interest_keywords"] = found_keywords
    
    # Deduplicate and clean
    for key in patterns:
        if isinstance(patterns[key], list) and key != "high_interest_keywords":
            patterns[key] = list(set(patterns[key]))[:10]  # Keep top 10 per category
    
    return patterns


def analyze_js_file(path: str) -> dict:
    findings = []
    suspicion_score = 0
    suspicious = False
    xss_sinks = []
    xss_score = 0
    
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        # try decode as utf-8, fallback latin1
        try:
            text = raw.decode("utf-8", errors="ignore")
        except:
            text = raw.decode("latin1", errors="ignore")
        lower = text.lower()

        # ==================== ORIGINAL MALWARE PATTERNS ====================
        # Patterns
        has_eval = bool(re.search(r"\beval\s*\(", text))
        has_new_func = bool(re.search(r"new\s+Function\s*\(", text))
        has_atob = bool(re.search(r"\batob\s*\(", text) or re.search(r"base64", lower))
        has_doc_write = bool(re.search(r"document\.write\s*\(", text))
        has_xhr = bool(re.search(r"XMLHttpRequest|fetch\(", text))

        if has_eval:
            findings.append("uses eval()")
            suspicion_score += 2
        if has_new_func:
            findings.append("uses new Function() (dynamic code)")
            suspicion_score += 2
        if has_atob:
            findings.append("base64 usage / atob()")
            suspicion_score += 1
        if has_doc_write:
            findings.append("uses document.write()")
            suspicion_score += 1
        if has_xhr:
            findings.append("performs XHR/fetch")
            suspicion_score += 1

        # look for long string literals (possible payload)
        literals = re.findall(r'["\']([A-Za-z0-9+/=]{100,})["\']', text)
        high_entropy_literal = False
        if literals:
            for lit in literals:
                e = shannon_entropy(lit)
                if e > 4.5:  # threshold for base64-like entropy
                    findings.append(f"high-entropy long string (len={len(lit)}, H={e:.2f})")
                    suspicion_score += 1
                    high_entropy_literal = True

        # overall text entropy
        ent = shannon_entropy(re.sub(r"\s+", "", text)[:5000])
        if ent > 4.5:
            findings.append(f"high entropy JS (H={ent:.2f})")
            suspicion_score += 1

        # Contextual suspiciousness: require multiple indicators
        if suspicion_score >= 4 and (
            (has_new_func or has_eval) and has_atob and has_xhr and (high_entropy_literal or ent > 4.5)
        ):
            suspicious = True
            findings.append("⚠️ Suspicious JS: multiple red flags detected (possible malware)")
        else:
            # If only high entropy and no other flags, likely minified library
            if suspicion_score <= 2 and ent > 4.5 and not (has_new_func or has_eval or has_atob or has_xhr):
                findings.append("Likely minified JS library (high entropy, no suspicious patterns)")

        # ==================== XSS SINK DETECTION ====================
        # DOM-based XSS sinks (innerHTML, innerText, etc.)
        xss_sink_patterns = [
            (r"\.innerHTML\s*=", "innerHTML assignment - DOM XSS sink"),
            (r"\.innerText\s*=", "innerText assignment - DOM XSS sink"),
            (r"\.textContent\s*=", "textContent assignment - potential XSS"),
            (r"document\.write\s*\(", "document.write() - possible XSS"),
            (r"\.insertAdjacentHTML", "insertAdjacentHTML - DOM XSS sink"),
            (r"\.append\s*\(", "append() with user input - potential XSS"),
            (r"eval\s*\(", "eval() execution - possible XSS"),
            (r"new\s+Function\s*\(", "new Function() - code execution sink"),
            (r"jQuery\(.*\)\.html\s*\(", "jQuery .html() - XSS sink"),
            (r"\$\(.*\)\.html\s*\(", "jQuery shorthand .html() - XSS sink"),
            (r"\.outerHTML\s*=", "outerHTML assignment - DOM XSS sink"),
        ]
        
        for pattern, desc in xss_sink_patterns:
            if re.search(pattern, text):
                xss_sinks.append(desc)
                xss_score += 2
        
        # Source patterns (user-controllable data)
        source_patterns = [
            (r"window\.location\.search", "URL query string - user input source"),
            (r"window\.location\.hash", "URL fragment - user input source"),
            (r"document\.location", "document.location - user input source"),
            (r"location\.search", "location.search - user input source"),
            (r"request\.args|request\.form|request\.data", "Flask/web form data"),
            (r"req\.query|req\.body", "Express.js request data"),
            (r"URLSearchParams", "URLSearchParams - URL parsing"),
            (r"localStorage\[", "localStorage access - potentially user-controlled"),
            (r"sessionStorage\[", "sessionStorage access - potentially user-controlled"),
        ]
        
        source_found = []
        for pattern, desc in source_patterns:
            if re.search(pattern, text):
                source_found.append(desc)
                xss_score += 1
        
        # Check for source → sink flows (suspicious pattern)
        if source_found and xss_sinks:
            xss_sinks.append(f"⚠️ XSS RISK: Found {len(source_found)} data sources and {len(xss_sinks)} sinks - possible DOM XSS chain")
            xss_score += 5
        
        # If high XSS score, flag it
        if xss_score >= 3:
            findings.append(f"🔴 POTENTIAL XSS VULNERABILITY - Score: {xss_score}")
            suspicion_score += 3

        # Add structured pattern extraction
        structured = extract_structured_patterns(text)
        
        return {
            "path": path,
            "findings": findings,
            "suspicion_score": suspicion_score,
            "suspicious": suspicious,
            "xss_sinks": xss_sinks,
            "xss_score": xss_score,
            "structured_patterns": structured
        }
    except Exception as e:
        return {
            "path": path,
            "error": str(e),
            "xss_sinks": [],
            "xss_score": 0
        }


