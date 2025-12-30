import whois
from datetime import datetime

def check_object (object) :
    if object and isinstance(object, list) :
        return object[0]
    
    return object

def check_domain(url):
    # Placeholder for domain analysis
    # Returns a dictionary of findings
    
    info = whois.whois(url)
    domain_name = check_object (info.domain_name)
    creation_date = check_object (info.creation_date).date()
    registrar = info.registrar
    name_servers = check_object (info.name_servers)
    status = info.status
    tld = domain_name[domain_name.find(".") + 1:]

    now = datetime.now().date()
    age_months = (now.year - creation_date.year) * 12 + now.month - creation_date.month

    return {
        "domain_name" : domain_name,
        "age_months" : age_months,
        "registrar" : registrar,
        "name_servers" : name_servers,
        "status" : status,
        "tld" : tld
    }