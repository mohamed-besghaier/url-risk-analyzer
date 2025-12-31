import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def check_tls(url):
    # Check the TLS/SSL certificate of a given URL

    hostname = urlparse(url).hostname.lstrip("www.")

    try :
    
        context = ssl.create_default_context()
        conn = context.wrap_socket (socket.socket(socket.AF_INET), server_hostname=hostname)

        conn.connect ((hostname, 443))

        cert = conn.getpeercert()

        valid = True

        issuer = cert["issuer"]
        issuer_org = None
        for tup in issuer:
            for key, value in tup:
                if key == "organizationName":
                    issuer_org = value
                    break
            if issuer_org:
                break
    
        subjectAltName = cert["subjectAltName"]

        san_domains = [tup[1] for tup in subjectAltName if tup[0] == "DNS"]
        if hostname not in san_domains:
            valid = False
    
        now = datetime.now().date()
        valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").date()
        valid_to = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").date()

        if (now < valid_from or now > valid_to) :
            valid = False

        conn.close()
    
        return { 
            "valid": valid,
            "issuer": issuer_org,
            "valid_from": valid_from,
            "valid_to": valid_to,
        }
    except Exception :
        return {
            "valid": False,
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
        }