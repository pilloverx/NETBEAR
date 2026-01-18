# config.py
"""
Unified security testing framework configuration
Supports: NetBear (web crawling), NextCloud (auth/IDOR/upload testing)
"""

# ============ GENERAL ============
REPORTS_DIR = "reports"
TARGETS_FILE = "targets.txt"
INDEX_FILE = f"{REPORTS_DIR}/index.txt"

TIMEOUT = 60000  # ms
ENABLE_TRACING = True
MAX_RETRIES = 2

# Proxy support for all modules
PROXIES = []  # e.g. ["http://proxy1:8080", "http://proxy2:8000", "socks5://proxy3:1080"]

# ============ NETBEAR (Web Crawling) ============
NETBEAR_SCOPES_FILE = "scopes.txt"
NETBEAR_MAX_DEPTH = 2
NETBEAR_MAX_PAGES_PER_DOMAIN = 15
NETBEAR_RATE_LIMIT_SEC = 1.5

# ============ NEXTCLOUD TESTING ============
# Target NextCloud instance
NEXTCLOUD_HOST = "https://nextcloud.example.com"  # Update with actual instance
NEXTCLOUD_USERNAME = ""  # Will be prompted interactively
NEXTCLOUD_PASSWORD = ""  # Will be prompted interactively
NEXTCLOUD_VERIFY_SSL = True

# Test parameters
NEXTCLOUD_MAX_WORKERS = 5  # Concurrent requests
NEXTCLOUD_TIMEOUT = 30  # seconds
NEXTCLOUD_RATE_LIMIT_SEC = 0.5  # Between requests to same endpoint

# IDOR Testing
NEXTCLOUD_IDOR_SAMPLE_SIZE = 50  # How many IDs to test
NEXTCLOUD_IDOR_ID_RANGES = {
    "file_id": (1, 1000),
    "share_id": (1, 500),
    "user_id": (1, 200)
}

# Upload Testing
NEXTCLOUD_UPLOAD_TIMEOUT = 10
NEXTCLOUD_MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB
NEXTCLOUD_DANGEROUS_EXTENSIONS = [
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phtml",
    ".sh", ".bash", ".exe", ".jar", ".jsp"
]

# Public Link Testing
NEXTCLOUD_PUBLIC_LINK_TIMEOUT = 5
NEXTCLOUD_PUBLIC_LINK_MAX_ATTEMPTS = 1000

# Auth Testing
NEXTCLOUD_AUTH_TEST_USERS = ["admin", "test", "guest"]

# ============ REPORTING ============
REPORT_FORMATS = ["json", "txt", "html"]  # Future: html reports
DEFAULT_REPORT_FORMAT = "json"

