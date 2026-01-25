# reporting.py
from datetime import datetime
import os
import json

def write_site_report(site_dir, url, domain, proxy, internal, external, red_flags, captcha_result, js_findings=None, forms_data=None, get_params=None, saved_resources=None):
    report_path = os.path.join(site_dir, "report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"NetBear Report\n")
        f.write(f"URL: {url}\nDomain: {domain}\nProxy: {proxy or 'None'}\n")
        f.write(f"Internal links: {len(internal)}\nExternal links: {len(external)}\n")
        f.write(f"Screenshot: {os.path.join(site_dir, 'screenshot.png')}\n\n")
        
        f.write("--- CAPTCHA Detection ---\n")
        f.write(f"{captcha_result}\n\n")
        
        # Forms & Parameters Section
        f.write("--- Discovered Forms ---\n")
        if forms_data:
            for idx, form in enumerate(forms_data, 1):
                f.write(f"Form {idx}:\n")
                f.write(f"  Action: {form['action']}\n")
                f.write(f"  Method: {form['method']}\n")
                f.write(f"  Inputs: {', '.join(form['inputs']) if form['inputs'] else 'None'}\n\n")
        else:
            f.write("No forms detected.\n\n")
        
        f.write("--- Potential GET Parameters ---\n")
        if get_params:
            f.write(", ".join(get_params) + "\n")
            f.write("(⚠️  IDOR Candidates: id, userId, betId, accountId, playerId, profileId, etc.)\n\n")
        else:
            f.write("No GET parameters found.\n\n")
        
        # Red Flags
        f.write("--- Red Flags ---\n")
        f.write("\n".join(red_flags) if red_flags else "None detected\n")
        
        # Captured APIs/XHR
        f.write("\n--- Captured XHR/API Endpoints ---\n")
        if saved_resources and saved_resources.get("xhr"):
            for xhr in saved_resources["xhr"]:
                f.write(f"  {xhr.get('url', 'Unknown URL')}\n")
        else:
            f.write("No XHR endpoints captured.\n")
        
        # Internal links for manual testing
        f.write("\n--- Internal Links (for manual testing) ---\n")
        for link in internal[:20]:  # Show top 20
            f.write(f"  {link}\n")
        
        # JS findings section
        f.write("\n--- Suspicious JavaScript Analysis ---\n")
        if js_findings:
            for idx, finding in enumerate(js_findings, 1):
                suspicious = finding.get("suspicious", False)
                suspicion_score = finding.get("suspicion_score", 0)
                f.write(f"JS File {idx}:\n")
                f.write(f"  Path: {finding.get('path','')}\n")
                f.write(f"  Suspicion Score: {suspicion_score}\n")
                f.write(f"  Suspicious: {'YES' if suspicious else 'NO'}\n")
                for v in finding.get("findings", []):
                    f.write(f"    - {v}\n")
                if "error" in finding:
                    f.write(f"  Error: {finding['error']}\n")
                
                # Add XSS Sinks if found
                if finding.get("xss_sinks"):
                    f.write("  XSS Sinks Found:\n")
                    for sink in finding["xss_sinks"]:
                        f.write(f"    - {sink}\n")
                
                # Add Structured Patterns if found
                structured = finding.get("structured_patterns", {})
                if any(structured.values()):
                    f.write("  Detected Patterns:\n")
                    if structured.get("api_endpoints"):
                        f.write(f"    - APIs: {', '.join(structured['api_endpoints'][:5])}\n")
                    if structured.get("param_names"):
                        f.write(f"    - Params: {', '.join(structured['param_names'][:5])}\n")
                    if structured.get("high_interest_keywords"):
                        f.write(f"    - Keywords: {', '.join(structured['high_interest_keywords'][:5])}\n")
                
                f.write("\n")
        else:
            f.write("No suspicious JS detected or no JS resources found.\n")
    
    return report_path


def write_crawl_summary(run_dir, crawl_stats):
    """Write a summary of the entire crawl session."""
    summary_path = os.path.join(run_dir, "CRAWL_SUMMARY.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("NETBEAR CRAWL SUMMARY - FDJ BOUNTY RECON\n")
        f.write("=" * 60 + "\n\n")
        
        f.write(f"Total pages crawled: {crawl_stats['total_pages']}\n")
        f.write(f"Successful: {crawl_stats['successful']}\n")
        f.write(f"Failed: {crawl_stats['failed']}\n")
        f.write(f"Total forms discovered: {crawl_stats['total_forms']}\n")
        f.write(f"Total unique GET params: {crawl_stats['total_params']}\n")
        f.write(f"Total XHR endpoints: {crawl_stats['total_xhr']}\n\n")
        
        f.write("--- High-Value Findings ---\n")
        f.write("1. Check forms_data for payment/account/profile forms\n")
        f.write("2. Review GET params in reports - look for: id, userId, betId, accountId\n")
        f.write("3. Test XHR endpoints manually in Burp Suite\n")
        f.write("4. Screenshots in each domain folder show dynamic content\n")
        f.write("5. Traces (if enabled) show request/response timings\n\n")
        
        f.write("--- Next Steps ---\n")
        f.write("1. Sort internal links by endpoint type (login, payment, profile)\n")
        f.write("2. Test IDOR on discovered endpoints with id/userId params\n")
        f.write("3. Check for logic flaws in betting flows\n")
        f.write("4. Test auth bypass on payment endpoints\n")
        f.write("5. Review XHR responses for sensitive data exposure\n")
    
    return summary_path


def append_index(index_file, timestamp, results):
    with open(index_file, "a", encoding="utf-8") as idx:
        for url, domain, status in results:
            idx.write(f"{timestamp}\t{domain}\t{url}\t{status}\n")


def export_to_har(run_dir, requests_list):
    """
    Export captured requests to HAR format for Burp Suite import.
    requests_list format: [{"method": "GET", "url": "...", "headers": {...}, "postData": "..."}, ...]
    """
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "NetBear", "version": "1.0"},
            "entries": []
        }
    }
    
    for idx, req in enumerate(requests_list, 1):
        headers = []
        if isinstance(req.get("headers"), dict):
            for k, v in req["headers"].items():
                headers.append({"name": k, "value": str(v)})
        
        # Parse query string
        from urllib.parse import urlparse, parse_qsl
        qs = []
        try:
            parsed = urlparse(req.get("url", ""))
            qs_list = parse_qsl(parsed.query)
            qs = [{"name": k, "value": v} for k, v in qs_list]
        except:
            pass

        entry = {
            "startedDateTime": datetime.now().isoformat() + "Z",
            "time": 100,
            "request": {
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": headers,
                "queryString": qs,
                "postData": req.get("postData") or None,
                "headersSize": -1,
                "bodySize": -1
            },
            "response": {
                "status": req.get("responseStatus", 200),
                "statusText": req.get("responseStatusText", "OK"),
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [{"name": k, "value": v} for k, v in req.get("responseHeaders", {}).items()],
                "content": {"size": 0, "mimeType": "application/octet-stream"},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1
            },
            "cache": {},
            "timings": {"wait": 50, "receive": 50, "send": 0}
        }
        har["log"]["entries"].append(entry)
    
    har_path = os.path.join(run_dir, "netbear_requests.har")
    with open(har_path, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2)
    
    return har_path


def export_to_curl(run_dir, requests_list):
    """
    Export captured requests as cURL commands.
    Optimized for Burp Suite: includes --insecure and proxy settings.
    """
    curl_path = os.path.join(run_dir, "requests.sh")
    results_dir = os.path.join(run_dir, "curl_results")
    error_log = os.path.join(run_dir, "errors.txt")
    
    with open(curl_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n")
        f.write("# NetBear cURL Export - Parallel Replay optimized for Burp\n")
        f.write("# To use Burp, set PROXY to your Burp listener address\n")
        f.write("PROXY=\"http://127.0.0.1:8080\"\n") 
        f.write("parallel=10\n")
        f.write("count=0\n")
        f.write(f"mkdir -p '{results_dir}'\n")
        f.write(f"rm -f '{error_log}'\n")
        f.write("echo '[+] Starting parallel replay... results in curl_results/'\n\n")
        
        for idx, req in enumerate(requests_list, 1):
            method = req.get("method", "GET")
            url = req.get("url", "")
            headers = req.get("headers", {})
            post_data = req.get("postData")
            
            # Use absolute paths for output to avoid directory issues
            output_file = os.path.join(results_dir, f"resp_{idx}.txt")
            header_file = os.path.join(results_dir, f"resp_{idx}_headers.txt")
            
            # Build the curl command string
            # -s (silent), -k (insecure/skip cert check), -v (verbose if debugging)
            # Use --proxy if the variable is set
            f.write(f"echo '({idx}/{len(requests_list)}) {method} {url}'\n")
            f.write(f"curl -s -k -X {method} ${{PROXY:+--proxy \"$PROXY\"}} \\\n")
            f.write(f"  -D '{header_file}' \\\n")
            f.write(f"  '{url}' \\\n")
            
            if isinstance(headers, dict):
                for k, v in headers.items():
                    safe_v = str(v).replace("'", "'\\''")
                    f.write(f"  -H '{k}: {safe_v}' \\\n")
            
            if post_data:
                if isinstance(post_data, str):
                    safe_data = post_data.replace("'", "'\\''")
                    f.write(f"  -d '{safe_data}' \\\n")
            
            f.write(f"  -o '{output_file}' || echo 'Failed request {idx}: {url}' >> '{error_log}' &\n\n")
            
            f.write("((count++))\n")
            f.write("if ((count % parallel == 0)); then wait; fi\n\n")
            
        f.write("wait\n")
        f.write("echo '[+] Done! Errors logged in errors.txt'\n")
    
    return curl_path

def export_js_structures(site_dir, js_findings):
    """Export extracted JS structures to JSON for Burp/manual review."""
    structures = {
        "timestamp": datetime.now().isoformat(),
        "js_files": []
    }
    
    for finding in js_findings:
        structured = finding.get("structured_patterns", {})
        if structured:
            structures["js_files"].append({
                "file": os.path.basename(finding.get("path", "unknown")),
                "tag": finding.get("tag", "normal"),
                "suspicion_score": finding.get("suspicion_score", 0),
                "xss_score": finding.get("xss_score", 0),
                "api_endpoints": structured.get("api_endpoints", []),
                "param_names": structured.get("param_names", []),
                "auth_related": structured.get("auth_related", []),
                "high_interest_keywords": structured.get("high_interest_keywords", []),
                "xss_sinks": finding.get("xss_sinks", [])
            })
    
    json_path = os.path.join(site_dir, "js_structures.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(structures, f, indent=2)
    
    return json_path