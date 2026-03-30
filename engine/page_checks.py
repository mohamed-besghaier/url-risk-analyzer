import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "sign in",
    "signin",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "confirm",
    "bank",
    "wallet",
    "payment",
}


def check_mixed_content(soup, tag):
    for x in soup.find_all(tag):
        src = x.get("src") or x.get("href")
        if src and src.startswith("http://"):
            return True
    return False


def is_external_resource(resource_url, base_hostname):
    parsed = urlparse(resource_url)
    if not parsed.netloc:
        return False
    return parsed.hostname != base_hostname


def find_suspicious_keywords(text):
    lowered = text.lower()
    return sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered)


def check_page(url):
    headers = {"Accept-Language": "en-US,en;q=0.9"}
    source = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
    source.raise_for_status()
    soup = BeautifulSoup(source.text, "lxml")
    parsed_source_url = urlparse(source.url)
    base_hostname = parsed_source_url.hostname
    scheme = parsed_source_url.scheme

    forms_found = 0
    external_scripts = 0
    mixed_content = False
    iframe_count = len(soup.find_all("iframe"))

    for x in soup.find_all("form"):
        if x.find_all("input", {"type": "password"}):
            forms_found += 1

    for x in soup.find_all("script"):
        if x.get("src"):
            resource_url = urljoin(source.url, x.get("src"))
            if is_external_resource(resource_url, base_hostname):
                external_scripts += 1

    if scheme == "https":
        if (
            check_mixed_content(soup, "script")
            or check_mixed_content(soup, "img")
            or check_mixed_content(soup, "iframe")
            or check_mixed_content(soup, "link")
        ):
            mixed_content = True

    visible_text = soup.get_text(" ", strip=True)
    suspicious_keywords = find_suspicious_keywords(visible_text)

    return {
        "forms_found": forms_found,
        "external_scripts": external_scripts,
        "mixed_content": mixed_content,
        "iframe_count": iframe_count,
        "suspicious_keywords": suspicious_keywords,
        "suspicious_keywords_count": len(suspicious_keywords),
    }
