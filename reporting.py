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
        
        entry = {
            "request": {
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "headers": headers,
                "postData": req.get("postData") or None
            },
            "response": {
                "status": 0,
                "statusText": "Unknown",
                "headers": [],
                "content": {"size": 0, "mimeType": "application/octet-stream"}
            },
            "cache": {},
            "timings": {"wait": -1, "receive": -1, "send": -1}
        }
        har["log"]["entries"].append(entry)
    
    har_path = os.path.join(run_dir, "netbear_requests.har")
    with open(har_path, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2)
    
    return har_path


def export_to_curl(run_dir, requests_list):
    """
    Export captured requests as cURL commands for easy copy-paste to Burp/terminal.
    Generates a .sh file with all cURL commands.
    """
    curl_path = os.path.join(run_dir, "requests.sh")
    with open(curl_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\n")
        f.write("# NetBear cURL Export - Import to Burp or run directly\n")
        f.write("# Usage: chmod +x requests.sh && ./requests.sh\n\n")
        
        for idx, req in enumerate(requests_list, 1):
            method = req.get("method", "GET")
            url = req.get("url", "")
            headers = req.get("headers", {})
            post_data = req.get("postData")
            
            f.write(f"# Request {idx}\n")
            f.write(f"curl -X {method} \\\n")
            f.write(f"  '{url}' \\\n")
            
            # Add headers
            if isinstance(headers, dict):
                for k, v in headers.items():
                    f.write(f"  -H '{k}: {v}' \\\n")
            
            # Add post data if present
            if post_data:
                f.write(f"  -d '{post_data}'\n\n")
            else:
                f.write(f"\n\n")
    
    return curl_path

def export_js_structures(site_dir, js_findings):
    """Export extracted JS structures to JSON for Burp/manual review."""
    structures = {
        "timestamp": datetime.now().isoformat(),
        "js_files": []
    }
    
    for finding in js_findings:
        if "patterns" in finding:
            structures["js_files"].append({
                "file": finding.get("file", "unknown"),
                "size_kb": finding.get("size_kb", 0),
                "tag": finding.get("tag", "normal"),
                "api_endpoints": finding["patterns"].get("api_endpoints", []),
                "param_names": finding["patterns"].get("param_names", []),
                "auth_related": finding["patterns"].get("auth_related", []),
                "high_interest_keywords": finding["patterns"].get("high_interest_keywords", []),
                "risk_indicators": finding.get("risk_indicators", [])
            })
    
    json_path = os.path.join(site_dir, "js_structures.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(structures, f, indent=2)
    
    return json_path