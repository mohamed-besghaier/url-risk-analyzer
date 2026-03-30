import ipaddress
from datetime import datetime
from urllib.parse import urlparse

import tldextract
import whois


def check_object(value):
    if value and isinstance(value, list):
        return value[0]
    return value


def extract_hostname(url):
    return (urlparse(url).hostname or "").strip().lower()


def is_ip_host(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def detect_domain_pattern_risk(extracted, hostname):
    labels = [label for label in extracted.subdomain.split(".") if label]
    reasons = []

    if hostname.startswith("xn--") or ".xn--" in hostname:
        reasons.append("punycode")
    if len(labels) >= 3:
        reasons.append("deep_subdomain")
    if hostname.count("-") >= 3:
        reasons.append("many_hyphens")
    if sum(char.isdigit() for char in hostname) >= 5:
        reasons.append("many_digits")
    if extracted.subdomain and extracted.domain and extracted.domain in extracted.subdomain:
        reasons.append("brand_like_subdomain")

    return reasons


def compute_age_months(creation_date):
    if not creation_date:
        return None

    if hasattr(creation_date, "date"):
        creation_date = creation_date.date()

    now = datetime.now().date()
    return (now.year - creation_date.year) * 12 + now.month - creation_date.month


def check_domain(url):
    hostname = extract_hostname(url)
    extracted = tldextract.extract(hostname)
    registered_domain = extracted.registered_domain or hostname
    info = whois.whois(registered_domain)

    domain_name = check_object(info.domain_name) or registered_domain
    creation_date = check_object(info.creation_date)
    registrar = info.registrar
    name_servers = check_object(info.name_servers)
    status = info.status or []
    if isinstance(status, str):
        status = [status]
    tld = extracted.suffix

    flags = [
        "clientDeleteProhibited",
        "serverDeleteProhibited",
        "clientTransferProhibited",
        "serverTransferProhibited",
    ]
    matched_flags = []

    for state in status:
        for flag in flags:
            if flag in state and flag not in matched_flags:
                matched_flags.append(flag)
        if len(matched_flags) == len(flags):
            break

    domain_pattern_risk = detect_domain_pattern_risk(extracted, hostname)

    return {
        "domain_name": domain_name,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "age_months": compute_age_months(creation_date),
        "registrar": registrar,
        "name_servers": name_servers,
        "status": matched_flags,
        "tld": tld,
        "ip_based_url": is_ip_host(hostname),
        "suspicious_domain_patterns": domain_pattern_risk,
    }
