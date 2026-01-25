import json
import os
from urllib.parse import urlparse, parse_qs

HAR_FILE = "/home/david/Boolean/NETBEAR/reports/run_20260123_112337/netbear_requests.har"
OUTPUT_FILE = "/home/david/Boolean/NETBEAR/reports/run_20260123_112337/MANUAL_TESTING_GUIDE.md"

# Keywords that suggest potential vulnerabilities
INTERESTING_PARAMS = [
    "id", "user", "account", "profile", "key", "token", "auth", "session", 
    "admin", "role", "group", "email", "phone", "uuid", "guid", "order", 
    "payment", "amount", "price", "url", "redirect", "path", "file"
]

def analyze_har_and_generate_guide(har_path, output_path):
    print(f"Analyzing {har_path}...")
    
    try:
        with open(har_path, 'r') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"Error reading HAR file: {e}")
        return

    entries = har_data.get('log', {}).get('entries', [])
    
    with open(output_path, 'w') as f:
        f.write("# Manual Web Security Testing Guide\n")
        f.write(f"**Source:** `{har_path}`\n")
        f.write(f"**Total Requests:** {len(entries)}\n\n")
        f.write("This guide provides step-by-step manual testing instructions for the captured requests. "
                "Use Burp Suite's Repeater or Intruder for these tests.\n\n")

        # Group by Domain to be organized
        requests_by_domain = {}
        
        for entry in entries:
            req = entry['request']
            url = req['url']
            method = req['method']
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            if domain not in requests_by_domain:
                requests_by_domain[domain] = []
            
            requests_by_domain[domain].append(entry)

        for domain, domain_entries in requests_by_domain.items():
            f.write(f"## Target: {domain}\n\n")
            
            for i, entry in enumerate(domain_entries, 1):
                req = entry['request']
                url = req['url']
                method = req['method']
                parsed_url = urlparse(url)
                path = parsed_url.path
                post_data = req.get('postData')
                
                # Check for query text (from our patched HAR or raw URL)
                query_params = req.get('queryString', [])
                if not query_params:
                     # Fallback if queryString is empty but URL has params
                     parsed = urlparse(url)
                     qs = parse_qs(parsed.query)
                     for k, v in qs.items():
                         query_params.append({'name': k, 'value': v[0]})

                # Determine if interesting
                interesting_reasons = []
                potential_params = []
                
                # 1. Check Query Params
                for param in query_params:
                    name = param['name']
                    potential_params.append(f"`{name}`")
                    for keyword in INTERESTING_PARAMS:
                        if keyword in name.lower():
                            interesting_reasons.append(f"**IDOR/PrivEsc Risk**: Parameter `{name}` looks valuable.")
                
                # 2. Check Body Content
                body_text = ""
                mime_type = ""
                
                if isinstance(post_data, dict):
                    mime_type = post_data.get('mimeType', '')
                    body_text = post_data.get('text', '')
                elif isinstance(post_data, str):
                    body_text = post_data
                    mime_type = "unknown/string"
                
                if body_text:
                    
                    if "json" in mime_type:
                        interesting_reasons.append("**Injection Risk**: JSON Body detected. Test for injection in values.")
                        # Try to parse JSON keys
                        try:
                            json_body = json.loads(body_text)
                            if isinstance(json_body, dict):
                                for k in json_body.keys():
                                    potential_params.append(f"JSON Key `{k}`")
                                    for keyword in INTERESTING_PARAMS:
                                        if keyword in k.lower():
                                            interesting_reasons.append(f"**IDOR/Logic Risk**: JSON key `{k}` is interesting.")
                        except:
                            pass
                    elif "form" in mime_type:
                        interesting_reasons.append("**Form Submission**: Check for XSS/SQLi in form fields.")
                
                # 3. Check for specific Sensitive files
                if path.endswith('.js'):
                    # Skip boring JS unless it was flagged in our system previously, 
                    # but here we just list it if it has params.
                    if not potential_params:
                        continue 
                
                # Filter out boring static assets with no params
                if not potential_params and method == "GET" and any(path.endswith(ext) for ext in ['.css', '.png', '.jpg', '.woff']):
                    continue

                # OUTPUT THE CHECKLIST ITEM
                f.write(f"### {i}. {method} {path}\n")
                f.write(f"- **Full URL**: `{url}`\n")
                if potential_params:
                    f.write(f"- **Parameters**: {', '.join(potential_params)}\n")
                
                if interesting_reasons:
                    f.write("- **⚠️ Analysis**:\n")
                    for reason in interesting_reasons:
                        f.write(f"    - {reason}\n")
                
                f.write("- **Manual Testing Steps**:\n")
                f.write(f"    1. [ ] **Send to Repeater**: (Ctrl+R in Burp)\n")
                
                # Generate specific steps based on context
                if potential_params:
                    f.write("    2. [ ] **Fuzz Parameters**: Try special chars `' \" < >` in inputs to check for errors (SQLi/XSS).\n")
                
                if "id" in str(potential_params).lower():
                    f.write("    3. [ ] **Test IDOR**: Change the ID values (increment/decrement) to see if you can access other users' data.\n")
                
                if method in ["POST", "PUT"]:
                    f.write("    4. [ ] **CSRF Check**: Remove Anti-CSRF tokens (if any) and replay.\n")
                    f.write("    5. [ ] **Broken Object Level Auth**: Can you POST data for another user ID?\n")
                
                f.write(f"    6. [ ] **Auth Bypass**: Remove `Cookie` or `Authorization` headers. Can you still access?\n")
                
                f.write("\n---\n")

    print(f"Guide generated at {output_path}")

if __name__ == "__main__":
    analyze_har_and_generate_guide(HAR_FILE, OUTPUT_FILE)
