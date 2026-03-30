import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests


def check_tls(url):
    hostname = urlparse(url).hostname or ""
    if hostname.startswith("www."):
        hostname = hostname[4:]

    redirected = False
    redirect_count = 0
    final_url = url
    final_scheme = urlparse(url).scheme

    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        redirected = len(response.history) > 0
        redirect_count = len(response.history)
        final_url = response.url
        final_scheme = urlparse(final_url).scheme
    except requests.RequestException:
        pass

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))

        cert = conn.getpeercert()

        issuer = cert["issuer"]
        issuer_org = None
        for tup in issuer:
            for key, value in tup:
                if key == "organizationName":
                    issuer_org = value
                    break
            if issuer_org:
                break

        valid = True
        try:
            ssl.match_hostname(cert, hostname)
        except ssl.CertificateError:
            valid = False

        now = datetime.now().date()
        valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").date()
        valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").date()

        if now < valid_from or now > valid_to:
            valid = False

        tls_present = final_scheme == "https"

        conn.close()

        return {
            "valid": valid,
            "tls_present": tls_present,
            "issuer": issuer_org,
            "redirected": redirected,
            "redirect_count": redirect_count,
            "final_url": final_url,
        }
    except Exception:
        return {
            "valid": False,
            "tls_present": final_scheme == "https" if final_scheme else None,
            "issuer": None,
            "redirected": redirected,
            "redirect_count": redirect_count,
            "final_url": final_url,
        }
