import whois
import tldextract
from datetime import datetime

def check_object (object) :
    if object and isinstance(object, list) :
        return object[0]
    
    return object

# Return a dict of domain informations
def check_domain(url) :
    info = whois.whois(url)
    domain_name = check_object (info.domain_name)
    creation_date = check_object (info.creation_date).date()
    registrar = info.registrar
    name_servers = check_object (info.name_servers)
    status = info.status
    tld = tldextract.extract(url).suffix
    
    FLAGS = ["clientDeleteProhibited", "serverDeleteProhibited", "clientTransferProhibited", "serverTransferProhibited"]
    res_FLAGS = []

    for st in status:
        for flag in FLAGS:
            if flag in st and flag not in res_FLAGS:
                res_FLAGS.append(flag)
        if len(res_FLAGS) == len(FLAGS):
            break

    now = datetime.now().date()
    age_months = (now.year - creation_date.year) * 12 + now.month - creation_date.month

    return {
        "domain_name" : domain_name,
        "age_months" : age_months,
        "registrar" : registrar,
        "name_servers" : name_servers,
        "status" : res_FLAGS,
        "tld" : tld
    }