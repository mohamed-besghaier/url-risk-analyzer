def calculate_score(domain_result, tls_result, page_result):
    # Very simple scoring logic for MVP
    # Returns LOW / MEDIUM / HIGH
    
    SAFE_REGISTRARS = [
        "MARKMONITOR",
        "GODADDY",
        "NAMECHEAP",
        "NETWORK SOLUTIONS",
        "TUCOWS DOMAINS",
        "GOOGLE",
        "AMAZON REGISTRAR",
        "BLUEHOST",
        "IONOS",
        "DYNADOT",
        "ENOM",
        "GANDI",
        "PUBLICDOMAINREGISTRY",
        "PUBLICDOMAINREGISTRY",
        "ALIBABA"
        ]
    
    SAFE_TLDS = [".com", ".org", ".net", ".gov", ".edu",
                 ".mil", ".int", ".co", ".io", ".us", ".uk", ".ca", ".de", ".fr", ".jp", ".au", ".ch", ".nl", ".se"]
    
    FLAGS = ["clientDeleteProhibited", "serverDeleteProhibited", "clientTransferProhibited", "serverTransferProhibited"]
    
    score = 0
    
    # Scoring : domain
    if any(reg in domain_result["registrar"].upper() for reg in SAFE_REGISTRARS) :
        score += 5
    
    if domain_result["age_months"] > 36 :
        score += 10
    
    if domain_result["tld"] in SAFE_TLDS :
        score += 10
    
    for status in domain_result["status"] :
        for flag in FLAGS[:]:
            if flag in status:
                score += 3.75
                FLAGS.remove(flag)
    
    # Scoring : tls
    if tls_result["valid"] :
        score += 10
        
    if tls_result["tls_present"] :
        score += 15
    
    # Scoring : page
    if page_result["forms_found"] == 0 :
        score += 15
    
    if page_result["external_scripts"] == 0 :
        score += 10
    
    if not page_result["mixed_content"] :
        score += 5
                 
    if score < 40 :
        return "HIGH", score
    
    if score < 70 :
        return "MEDIUM", score

    return "LOW", score