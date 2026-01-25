import json
import os
import sys

# Add the NETBEAR directory to path so we can import reporting
sys.path.append('/home/david/Boolean/NETBEAR')
from reporting import export_to_curl

run_dir = "/home/david/Boolean/NETBEAR/reports/run_20260123_112337"
har_path = os.path.join(run_dir, "netbear_requests.har")

# Load requests from HAR
with open(har_path, 'r') as f:
    har_data = json.load(f)

requests_list = []
for entry in har_data.get('log', {}).get('entries', []):
    req = entry.get('request', {})
    
    # Convert HAR headers list back to dict for export_to_curl
    headers_dict = {h['name']: h['value'] for h in req.get('headers', [])}
    
    post_data_info = req.get('postData')
    post_data_text = None
    if isinstance(post_data_info, dict):
        post_data_text = post_data_info.get('text')
    elif isinstance(post_data_info, str):
        post_data_text = post_data_info

    req_info = {
        "method": req.get('method'),
        "url": req.get('url'),
        "headers": headers_dict,
        "postData": post_data_text
    }
    requests_list.append(req_info)

# Regenerate requests.sh
new_path = export_to_curl(run_dir, requests_list)
print(f"Regenerated: {new_path}")
