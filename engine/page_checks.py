import requests
from bs4 import BeautifulSoup

def check_mixed_content (soup, tag) :
    for x in soup.find_all(tag) :
        src = x.get("src") or x.get("href")
        if x.get("src") :
            if src and src.split("://")[0] == "http":
                return True
    return False

# Check a URL and return a dict with login forms count, external scripts count, and mixed content flag
def check_page(url) :
    headers = {"Accept-Language": "en-US,en;q=0.9"}
    source = requests.get (url, headers=headers)
    soup = BeautifulSoup (source.text, "lxml")
    scheme = source.url.split("://")
    
    forms_found = 0
    external_scripts = 0
    mixed_content = False
    
    for x in soup.find_all("form"):
        if x.find_all("input", {"type": "password"}) :
            forms_found += 1
    
    for x in soup.find_all("script") :
        if x.get("src") :
            external_scripts += 1
    
    if scheme[0] == "https" :
        if check_mixed_content(soup, "script") or \
            check_mixed_content(soup, "img") or \
            check_mixed_content(soup, "iframe") or \
            check_mixed_content(soup, "link"):
                mixed_content = True
            
    return {
        "forms_found" : forms_found,
        "external_scripts" : external_scripts,
        "mixed_content" : mixed_content
    }