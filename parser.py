# parser.py
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urljoin, urlparse, parse_qs

def parse_links(html: str, base_url: str):
    soup = BeautifulSoup(html, "html.parser")
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    base_domain = tldextract.extract(base_url).registered_domain

    internal, external = [], []
    for link in links:
        if not isinstance(link, str):
            continue  # Skip non-string hrefs
        abs_link = urljoin(base_url, link)
        link_domain = tldextract.extract(abs_link).registered_domain
        (internal if link_domain == base_domain else external).append(abs_link)
    return internal, external


def parse_forms_and_params(html: str, base_url: str):
    """
    Extract forms (action, method, inputs) and GET parameters from HTML.
    Returns dict with 'forms' and 'get_params' keys.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    get_params = set()

    # Extract forms
    for form in soup.find_all("form"):
        action = urljoin(base_url, str(form.get("action", "")))
        method_value = form.get("method", "GET")
        method = str(method_value).upper() if method_value else "GET"
        inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    # Extract GET parameters from all links
    for a in soup.find_all("a", href=True):
        abs_link = urljoin(base_url, str(a["href"]))
        parsed = urlparse(abs_link)
        if parsed.query:
            params = parse_qs(parsed.query).keys()
            get_params.update(params)

    return {
        "forms": forms,
        "get_params": sorted(list(get_params))
    }