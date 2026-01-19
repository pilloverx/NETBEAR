# NetBear 🐻

Playwright-powered web reconnaissance crawler built for bug bounty hunting.

**Features**
- Depth crawling with scope validation
- Form & GET parameter extraction
- Full JS/XHR capture + interest tagging (HIGH/CRITICAL)
- Screenshots, Playwright traces & HAR export for Burp Suite
- Rich console output & JSON reporting
- Modules for Nextcloud assessment & FDJ-style bounty recon

**Quick Start**

```bash
git clone https://github.com/pilloverx/NETBEAR.git
cd NETBEAR
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install
python main.py                # or python netbear_crawler.py
