# fetcher.py
import os, random, asyncio, traceback
from typing import Any
from playwright.sync_api import sync_playwright
from config import PROXIES, TIMEOUT

def get_random_proxy():
    """Select a random proxy from config."""
    if not PROXIES:
        return None
    return random.choice(PROXIES)

def fetch_page_with_capture(url, screenshot_path, site_dir, proxy=None, timeout=TIMEOUT, retries=2, enable_trace=True):
    """
    Fetches a webpage, saves a screenshot and trace (optional), and returns HTML + captured JS/XHR info.
    """
    html_content = ""
    saved_resources = {"js": [], "xhr": []}
    last_error = None

    # Use random proxy if not explicitly provided
    proxy = proxy or get_random_proxy()

    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    for attempt in range(1, retries + 2):
        try:
            with sync_playwright() as p:
                browser_args: dict[str, Any] = {"headless": True}

                # Configure proxy if available
                if proxy:
                    browser_args["proxy"] = {"server": proxy}
                    print(f"[NetBear] Using proxy: {proxy}")

                browser = p.chromium.launch(**browser_args)
                context = browser.new_context()

                trace_path = os.path.join(site_dir, "trace.zip")
                if enable_trace:
                    context.tracing.start(screenshots=True, snapshots=True, sources=True)

                page = context.new_page()
                page.set_default_timeout(timeout)

                # Capture JS and XHR requests
                def on_response(response):
                    try:
                        ct = response.headers.get("content-type", "")
                        
                        # High-interest keywords for this domain/target
                        HIGH_INTEREST_KEYWORDS = [
                            "appointment", "booking", "patient", "doctor", "slot",
                            "availability", "calendar", "prescription", "id"
                        ]
                        
                        if "javascript" in ct:
                            body = response.text()
                            
                            # Determine interest level
                            interest_tag = "normal"
                            if any(kw in body.lower() for kw in HIGH_INTEREST_KEYWORDS):
                                interest_tag = "HIGH_INTEREST"
                            if any(kw in body.lower() for kw in ["eval", "new Function", "innerHTML", "token"]):
                                interest_tag = "CRITICAL"
                            
                            js_path = os.path.join(site_dir, f"res_{len(saved_resources['js'])}-{interest_tag}.js")
                            with open(js_path, "w", encoding="utf-8") as f:
                                f.write(body)
                            saved_resources["js"].append({
                                "url": response.url,
                                "path": js_path,
                                "tag": interest_tag,
                                "size": len(body)
                            })
                        elif "json" in ct or "xhr" in response.url:
                            body = response.text()
                            xhr_path = os.path.join(site_dir, f"xhr_{len(saved_resources['xhr'])}.json")
                            with open(xhr_path, "w", encoding="utf-8") as f:
                                f.write(body)
                            saved_resources["xhr"].append({"url": response.url, "path": xhr_path})
                    except Exception:
                        pass

                page.on("response", on_response)
                try:
                    page.goto(url)
                except PlaywrightTimeoutError as te:
                    print(f"[Attempt {attempt}] ❌ Timeout fetching {url}: {te}")
                    last_error = ("timeout", str(te))
                    browser.close()
                    continue
                except Exception as e:
                    print(f"[Attempt {attempt}] ❌ Error during page.goto for {url}: {e}")
                    last_error = ("goto_error", str(e))
                    browser.close()
                    continue

                html_content = page.content()
                page.screenshot(path=screenshot_path)

                if enable_trace:
                    context.tracing.stop(path=trace_path)

                browser.close()
                print(f"[NetBear] Fetched {url} ✅")
                return html_content, saved_resources

        except PlaywrightTimeoutError as te:
            print(f"[Attempt {attempt}] ❌ Timeout fetching {url}: {te}")
            last_error = ("timeout", str(te))
        except Exception as e:
            print(f"[Attempt {attempt}] ❌ Error fetching {url}: {e}")
            traceback.print_exc()
            last_error = ("exception", str(e))

    print(f"[NetBear] Failed to fetch {url} after {retries+1} attempts. Last error: {last_error}")
    return {"error": last_error, "url": url}, saved_resources
