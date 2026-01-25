# netbear_crawler.py
import os
import datetime
import time
import tldextract
from collections import deque
from rich.console import Console
from rich.progress import track
from rich.panel import Panel
from rich import box

# Local imports
import config
from config import REPORTS_DIR, TARGETS_FILE, INDEX_FILE, TIMEOUT
from utils import ensure_dir, sanitize_filename
from fetcher import fetch_page_with_capture, get_random_proxy
from js_analyser import analyze_js_file
from parser import parse_links, parse_forms_and_params
from detectors import detect_captcha, detect_red_flags
from reporting import export_js_structures, write_site_report, write_crawl_summary, append_index, export_to_har, export_to_curl
from auth import LoginHandler
from fuzzer import ParamFuzzer

console = Console()

# Load in-scope domains from scopes.txt
SCOPES_FILE = "scopes.txt"
ALLOWED_DOMAINS = set()

def load_scopes():
    """Load allowed domains from scopes.txt"""
    global ALLOWED_DOMAINS
    if os.path.exists(SCOPES_FILE):
        with open(SCOPES_FILE, "r", encoding="utf-8") as f:  # Specify UTF-8 encoding
            ALLOWED_DOMAINS = {
                line.strip() for line in f 
                if line.strip() and not line.startswith("#")
            }
        console.print(f"[cyan]✓ Loaded {len(ALLOWED_DOMAINS)} allowed domains from {SCOPES_FILE}[/cyan]")
    else:
        console.print(f"[yellow]⚠️  {SCOPES_FILE} not found, using permissive mode[/yellow]")


def is_in_scope(url):
    """Check if URL is in scope based on domain allowlist"""
    if not ALLOWED_DOMAINS:
        return True  # Permissive if no scopes loaded

    domain = tldextract.extract(url).top_domain_under_public_suffix

    # Check exact match
    if domain in ALLOWED_DOMAINS:
        return True
    
    # Check subdomain matches (e.g., payment.unibet.com matches unibet.com)
    for allowed in ALLOWED_DOMAINS:
        if url.endswith(allowed) or f".{allowed}" in url:
            return True
    
    return False


def extract_internal_links_for_depth(html: str, base_url: str):
    """
    Extract internal links that are safe for depth crawling.
    Filters out: stylesheets, images, media, scripts (to focus on pages).
    """
    internal, _ = parse_links(html, base_url)
    
    # Filter out common non-page resources
    filtered = [
        link for link in internal
        if not any(link.lower().endswith(ext) for ext in [
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico',
            '.pdf', '.zip', '.exe', '.mp4', '.mp3', '.webm', '.svg'
        ])
    ]
    
    return filtered


def crawl_url(url, run_dir, proxy=None, collect_forms=True):
    """
    Crawl a single URL: capture HTML, analyze JS, detect red flags, write reports.
    Returns a tuple: (url, domain, status_message, internal_links, forms_data, get_params)
    """
    domain = tldextract.extract(url).top_domain_under_public_suffix or "unknown_domain"
    site_dir = os.path.join(run_dir, sanitize_filename(domain))
    ensure_dir(site_dir)

    screenshot_path = os.path.join(site_dir, "screenshot.png")

    try:
        html, saved_resources = fetch_page_with_capture(
            url,
            screenshot_path,
            site_dir,
            proxy=proxy,
            timeout=TIMEOUT,
            retries=config.MAX_RETRIES,
            enable_trace=config.ENABLE_TRACING
        )

        # Ensure html is a string
        if isinstance(html, dict):
            html = html.get("html", "")
        
        # Parse internal/external links
        internal, external = parse_links(html, url)

        # Parse forms and params
        parsed_data = parse_forms_and_params(html, url)
        forms_data = parsed_data["forms"]
        get_params = parsed_data["get_params"]

        # Captcha detection
        captcha_result = detect_captcha(html)

        # Collect all JS and XHR resource URLs for deeper analysis
        js_xhr_urls = [
            res["url"] for cat in ["js", "xhr"]
            for res in saved_resources.get(cat, []) if "url" in res
        ]

        # Red flag detection
        red_result = detect_red_flags(url, html, internal + external, js_xhr_urls)
        red_flags = red_result["flags"]
        score = red_result["score"]

                # Analyze JS files locally
        js_findings = []
        for js_info in saved_resources.get("js", []):
            js_result = analyze_js_file(js_info["path"])
            js_result["tag"] = js_info.get("tag", "normal")  # Add tag from fetcher
            js_findings.append(js_result)

        # Export structured JS patterns
        js_structures_path = export_js_structures(site_dir, js_findings)

        # Save structured report
        write_site_report(
            site_dir, url, domain, proxy, internal, external, red_flags, 
            captcha_result, js_findings, forms_data, get_params, saved_resources
        )
        # Get internal links for depth crawling
        internal_for_depth = extract_internal_links_for_depth(html, url)

        return (url, domain, "✅ Success", internal_for_depth, forms_data, get_params, saved_resources.get("all_requests", []))

    except Exception as e:
        return (url, domain, f"❌ Failed: {str(e)}", [], None, None, [])


def crawl_domain_with_depth(start_url, run_dir, max_depth=2, max_pages_per_domain=15, delay_sec=1.5):
    """
    BFS-based crawl with depth limit, respecting scope and rate limits.
    Returns: list of (url, domain, status, forms, params) for aggregation.
    """
    visited = set()
    queue = deque([(start_url, 0)])
    domain_results = []
    crawl_stats = {"total_forms": 0, "total_params": 0, "total_links": 0}

    base_domain = tldextract.extract(start_url).top_domain_under_public_suffix
    pages_crawled_for_domain = 0

    while queue and pages_crawled_for_domain < max_pages_per_domain:
        url, depth = queue.popleft()

        # Skip if already visited, out of depth, out of scope
        if url in visited or depth > max_depth or not is_in_scope(url):
            continue

        visited.add(url)
        
        # Rate limiting
        time.sleep(delay_sec)

        # Single URL crawl
        result = crawl_url(url, run_dir, proxy=get_random_proxy(), collect_forms=True)
        url_result, domain, status, internal_links, forms_data, get_params, all_reqs = result

        domain_results.append(result)
        pages_crawled_for_domain += 1

        # Track stats
        if forms_data:
            crawl_stats["total_forms"] += len(forms_data)
        if get_params:
            crawl_stats["total_params"] += len(get_params)
        crawl_stats["total_links"] += len(internal_links)

        # Queue internal links for next depth
        if depth < max_depth and "Success" in status:
            for link in internal_links[:8]:  # Limit branching to avoid explosion
                if link not in visited:
                    queue.append((link, depth + 1))

        depth_indicator = f"[D{depth}]"
        console.print(
            f"{depth_indicator} [cyan]{url}[/] → [bold]{status}[/] "
            f"(forms: {len(forms_data) if forms_data else 0}, params: {len(get_params) if get_params else 0})"
        )

    return domain_results, crawl_stats


def main():
    console.print(Panel.fit(
        "[bold blue]🚀 NetBear Web Scanner - FDJ Bounty Mode[/bold blue]\n"
        "[cyan]Depth-aware, scope-limited, rate-controlled recon crawler[/cyan]",
        box=box.ROUNDED
    ))

    # Load scope allowlist
    load_scopes()

    # 1. Ensure directories exist
    ensure_dir(REPORTS_DIR)

    # 2. Verify targets file exists
    if not os.path.exists(TARGETS_FILE):
        console.print(f"[bold red]No {TARGETS_FILE} found![/bold red]")
        console.print("➡️  Create it with one URL per line, e.g.:")
        console.print("   https://www.unibet.com\n   https://www.mariacasino.com")
        return

    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not targets:
        console.print(f"[yellow]⚠️ No valid URLs found in {TARGETS_FILE}![/yellow]")
        return

    # 3. Setup report run directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(REPORTS_DIR, f"run_{timestamp}")
    ensure_dir(run_dir)

    console.print(f"\n[bold green]✓ Targets loaded:[/bold green] {len(targets)} site(s)")
    console.print(f"[cyan]Reports will be saved in:[/cyan] {run_dir}\n")

    # 4. Crawl loop with depth
    index_entries = []
    full_crawl_data = []
    aggregate_stats = {"total_pages": 0, "successful": 0, "failed": 0, 
                       "total_forms": 0, "total_params": 0, "total_xhr": 0}

    domain_results = []  # Initialize domain_results as an empty list

    for target_idx, url in enumerate(targets, 1):
        console.print(
            Panel.fit(
                f"[bold yellow]Target {target_idx}/{len(targets)}[/bold yellow]: {url}",
                box=box.SQUARE
            )
        )

        domain_results, domain_stats = crawl_domain_with_depth(
            url, 
            run_dir, 
            max_depth=2,           # Home + 1 level deep
            max_pages_per_domain=15,
            delay_sec=1.5          # 1.5 sec between requests
        )

        # Aggregate results
        for result in domain_results:
            url_res, domain, status, _, _, _, _ = result
            index_entries.append((url_res, domain, status))
            aggregate_stats["total_pages"] += 1
            if "Success" in status:
                aggregate_stats["successful"] += 1
            else:
                aggregate_stats["failed"] += 1

        aggregate_stats["total_forms"] += domain_stats["total_forms"]
        aggregate_stats["total_params"] += domain_stats["total_params"]
        full_crawl_data.append(domain_results) # Store full depth results for HAR export

    # 5. Write session index and summary
    append_index(INDEX_FILE, timestamp, index_entries)
    summary_path = write_crawl_summary(run_dir, aggregate_stats)
    
    # 6. Generate HAR export for Burp import
    global_requests = []
    all_params = []
    all_urls = []
    
    for domain_batch in full_crawl_data:
        if not isinstance(domain_batch, list): continue
        for result in domain_batch:
            if len(result) >= 7:
                url_res, _, _, _, forms_data, get_params, all_reqs = result
                if all_reqs:
                    global_requests.extend(all_reqs)
                if get_params:
                    all_params.extend(get_params)
                all_urls.append(url_res)
    
    har_path = "N/A"
    if global_requests:
        har_path = export_to_har(run_dir, global_requests)
        curl_path = export_to_curl(run_dir, global_requests)
        console.print(f"\n[green]✅ Total {len(global_requests)} requests exported to HAR/cURL[/green]")
    
    # 7. Generate fuzzing guide with flagged parameters
    if all_params:
        fuzzer = ParamFuzzer()
        fuzzing_report = fuzzer.create_fuzzing_report(run_dir, all_params, all_urls)
        console.print(f"[green]✅ Fuzzing guide:[/green] {fuzzing_report}")

    console.print(f"\n" + "=" * 60)
    console.print(f"[bold green]🎯 Crawl Complete![/bold green]")
    console.print(f"[cyan]Total pages:[/cyan] {aggregate_stats['total_pages']}")
    console.print(f"[cyan]Successful:[/cyan] {aggregate_stats['successful']}")
    console.print(f"[cyan]Forms discovered:[/cyan] {aggregate_stats['total_forms']}")
    console.print(f"[cyan]Unique GET params:[/cyan] {aggregate_stats['total_params']}")
    console.print(f"\n[underline]Reports:[/underline] {run_dir}")
    console.print(f"[underline]Summary:[/underline] {summary_path}")
    console.print(f"[underline]HAR for Burp:[/underline] {har_path if global_requests else 'N/A'}")
    console.print("=" * 60)
    console.print(f"\n[bold cyan]💡 Next Steps:[/bold cyan]")
    console.print(f"1. Open {har_path if global_requests else 'HAR file'} in Burp → Import to Sitemap")
    console.print(f"2. Review FUZZING_GUIDE.txt for high-risk parameters")
    console.print(f"3. Use fuzzer.py payloads for Intruder testing")
    console.print(f"4. Check for XSS/SQLi in JS findings (js_analyser output)")
    console.print(f"5. Test IDOR on parameters flagged in fuzzing guide")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"[bold red]Fatal Error:[/bold red] {str(e)}")
