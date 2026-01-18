# NEXTCLOUD_ASSESSMENT.md
# NextCloud Vulnerability Assessment Module

## Overview

NetBear has been upgraded to include comprehensive NextCloud vulnerability assessment capabilities. The framework is now modular, supporting both:

1. **NetBear** - Traditional web crawling and reconnaissance
2. **NextCloud Tester** - NextCloud-specific vulnerability assessment

## Features

### Interactive CLI
- Menu-driven interface for selecting assessment modes
- Real-time progress feedback with Rich console
- JSON report generation for all findings

### NextCloud Assessment Tests

#### 1. **Reconnaissance (Recon)**
- System version detection
- User enumeration
- Share enumeration
- Public link discovery
- **Severity**: Info/Medium
- **Use Case**: Mapping target capabilities

#### 2. **IDOR Testing**
- File ID enumeration
- Share ID enumeration
- User ID enumeration
- Direct file access attempts
- **Severity**: High/Critical
- **Use Case**: Identifying unauthorized access vulnerabilities

#### 3. **Upload Abuse**
- File type bypass detection
- RCE payload testing (PHP, JSP, ASPX)
- Stored XSS vector testing
- Upload limit testing
- **Severity**: Critical/High
- **Use Case**: Finding code execution and data injection vectors

#### 4. **Auth Escalation**
- Admin endpoint access testing
- Role modification attempts
- Token security validation
- Permission bypass testing
- Group escalation testing
- **Severity**: Critical/High
- **Use Case**: Privilege escalation vectors

#### 5. **Public Link Testing**
- Public share enumeration
- Token enumeration and brute-forcing
- Share access control validation
- Password bypass attempts
- **Severity**: High/Medium
- **Use Case**: Unauthorized access via public links

## Installation

```bash
cd c:\Users\Agya\BOOLEAN\Netbear
pip install -r requirements.txt
```

## Quick Start

### Run Interactive CLI

```bash
python main.py
```

You'll see the main menu:
```
🔒 NetBear Security Framework
Modular vulnerability assessment & reconnaissance

Select Mode:

  [1] NetBear - Web Crawling & Reconnaissance
  [2] NextCloud - Vulnerability Assessment
  [3] Exit
```

### NextCloud Assessment Workflow

1. **Select Mode 2** (NextCloud)
2. **Enter target details**:
   - NextCloud Host (e.g., https://nextcloud.example.com)
   - Username (authenticated user account)
   - Password
3. **Select tests** to run:
   - Recon (enumerate system)
   - IDOR (test ID access)
   - Upload (test file upload)
   - Auth (test privilege escalation)
   - Public Links (test share security)
   - All (run all tests)
4. **Adjust test parameters** (optional):
   - IDOR sample size (default: 50)
   - Concurrent workers (default: 5)
   - Rate limit (default: 0.5 sec)
5. **Review results** in real-time
6. **Save JSON report** automatically

### Output Structure

```
reports/
└── 20260114_150000/
    └── nextcloud_report.json
```

### Report Format

```json
{
  "session_id": "20260114_150000",
  "mode": "nextcloud",
  "timestamp": "2026-01-14T15:00:00",
  "findings": [
    {
      "type": "user_enumeration",
      "severity": "high",
      "count": 42,
      "users": ["user1", "user2", "admin"],
      "description": "Exposed 42 user IDs",
      "endpoint": "/ocs/v2.php/apps/provisioning_api/api/v1/users",
      "impact": "User enumeration can aid in brute force attacks"
    },
    {
      "type": "file_id_idor",
      "severity": "high",
      "count": 15,
      "endpoint": "/remote.php/dav/files/",
      "vulnerable_ids": [
        {"file_id": 1, "status": 200, "size": 12345}
      ],
      "description": "File IDs may be enumerable",
      "impact": "Direct file access without authorization"
    }
  ],
  "summary": {
    "total_tests": 5,
    "findings_count": 8,
    "critical": 2,
    "high": 5,
    "medium": 1,
    "low": 0
  }
}
```

## Configuration

Edit `config.py` to customize behavior:

```python
# NextCloud Target
NEXTCLOUD_HOST = "https://nextcloud.example.com"
NEXTCLOUD_VERIFY_SSL = True

# Test Parameters
NEXTCLOUD_MAX_WORKERS = 5           # Parallel connections
NEXTCLOUD_TIMEOUT = 30              # Request timeout
NEXTCLOUD_RATE_LIMIT_SEC = 0.5      # Delay between requests

# IDOR Testing
NEXTCLOUD_IDOR_SAMPLE_SIZE = 50     # How many IDs to test
NEXTCLOUD_IDOR_ID_RANGES = {
    "file_id": (1, 1000),
    "share_id": (1, 500),
    "user_id": (1, 200)
}

# Upload Testing
NEXTCLOUD_DANGEROUS_EXTENSIONS = [
    ".php", ".phtml", ".php3", ".php4", ".php5",
    ".sh", ".bash", ".exe", ".jar", ".jsp"
]

# Public Link Testing
NEXTCLOUD_PUBLIC_LINK_MAX_ATTEMPTS = 1000
```

## Usage Examples

### Example 1: Full Assessment

```
python main.py
→ Select: 2 (NextCloud)
→ Host: https://nc.example.com
→ User: testuser
→ Pass: [password]
→ Tests: 6 (All Tests)
→ Wait for completion
→ Review report in reports/[session_id]/nextcloud_report.json
```

### Example 2: IDOR-Only Assessment

```
python main.py
→ Select: 2 (NextCloud)
→ Enter credentials
→ Tests: 2 (IDOR)
→ Customize IDOR sample size: 100
→ Run and review file/share ID findings
```

### Example 3: Upload Vulnerability Testing

```
python main.py
→ Select: 2 (NextCloud)
→ Enter credentials
→ Tests: 3 (Upload Abuse)
→ Check for PHP/RCE/XSS payloads
```

## Vulnerability Severity Ratings

- **Critical**: System-wide compromise (RCE, auth bypass, complete IDOR)
- **High**: Significant data access or modification (upload abuse, privilege escalation)
- **Medium**: Information disclosure or limited impact (recon, public link leaks)
- **Low**: Minor issues requiring specific conditions
- **Info**: Informational findings (versions, capabilities)

## Best Practices

### Scope & Authorization
- ✅ Only test NextCloud instances you own or have permission to test
- ✅ Get written authorization before security testing
- ✅ Test during maintenance windows if possible
- ❌ Do NOT test production systems without consent

### Rate Limiting
- Use default 0.5 sec rate limit to avoid triggering WAF/IDS
- Increase for high-security environments (1-2 sec)
- Monitor for blocking/rate limiting responses

### Test Order
1. Start with **Recon** to understand system capabilities
2. Run **IDOR** tests on specific endpoints
3. Test **Upload** with carefully crafted payloads
4. Run **Auth** escalation tests last
5. Focus on **Public Links** if externally exposed

### Report Interpretation

- **High count findings** = systematic vulnerability (strong signal)
- **Mixed results** = configuration issue or WAF interference
- **No findings** = either secure or tests need tuning
- **Review every finding** before reporting

## Troubleshooting

### Connection Fails
- Verify host URL (should start with https://)
- Check username/password
- Ensure network connectivity
- Verify SSL certificates if NEXTCLOUD_VERIFY_SSL=True

### No Findings Despite Vulnerabilities
- Increase IDOR_SAMPLE_SIZE (test more IDs)
- Lower RATE_LIMIT_SEC (faster testing, may trigger WAF)
- Check if endpoints are rate-limited
- Try different test cases

### Slow Performance
- Reduce MAX_WORKERS (fewer parallel connections)
- Increase RATE_LIMIT_SEC (more spacing)
- Test during off-peak hours
- Check network connectivity

### SSL Certificate Errors
In `config.py`, set:
```python
NEXTCLOUD_VERIFY_SSL = False  # Use only for testing!
```

## Module Architecture

```
nextcloud/
├── __init__.py
├── nc_recon.py           # Enumeration & discovery
├── nc_idor.py            # ID enumeration tests
├── nc_upload.py          # File upload & RCE/XSS tests
├── nc_auth.py            # Privilege escalation tests
└── nc_public_links.py    # Public share testing

nextcloud_tester.py        # Orchestrator
interactive_cli.py         # CLI interface
config.py                  # Configuration
main.py                    # Entry point
```

## Extending the Framework

### Adding a New Test Module

1. Create `nextcloud/nc_newtest.py`:
```python
class NCNewTest:
    def __init__(self, session):
        self.session = session
        self.findings = []
    
    def run(self):
        # Implement tests
        return self.findings
```

2. Register in `nextcloud_tester.py`:
```python
self.test_modules = {
    ...
    "newtest": NCNewTest,
}
```

3. Update CLI in `interactive_cli.py`:
```python
test_options = [
    ("6", "New Test - Description"),
    ...
]
```

### Adding a New Target Type (Beyond NextCloud)

The framework supports multiple target types. To add a new one:

1. Create `new_target/` directory
2. Implement target-specific modules
3. Create `new_target_tester.py`
4. Update `interactive_cli.py` main_menu()
5. Add configuration in `config.py`

## Reporting Vulnerabilities

When reporting findings to vendors:

1. **Include JSON report** as evidence
2. **Describe impact** in business terms
3. **Provide PoC steps** to reproduce
4. **Suggest remediation** where applicable
5. **Include timeline** (discovery date, disclosure deadline)

## References

- [NextCloud Security](https://nextcloud.com/security/)
- [OCS API Documentation](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/)
- [WebDAV Protocol](https://tools.ietf.org/html/rfc4918)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

**Last Updated**: January 14, 2026  
**Framework Version**: NetBear v2.1 (NextCloud Edition)  
**Author**: Security Team
