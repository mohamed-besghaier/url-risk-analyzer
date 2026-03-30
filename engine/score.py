def calculate_score(domain_result, tls_result, page_result):
    risk_points = 0

    age_months = domain_result.get("age_months")
    if age_months is None:
        risk_points += 10
    elif age_months < 3:
        risk_points += 30
    elif age_months < 12:
        risk_points += 15

    if domain_result.get("ip_based_url"):
        risk_points += 35

    risk_points += min(len(domain_result.get("suspicious_domain_patterns", [])) * 10, 30)

    if not tls_result.get("tls_present"):
        risk_points += 25

    if not tls_result.get("valid"):
        risk_points += 20

    if tls_result.get("redirect_count", 0) >= 3:
        risk_points += 15
    elif tls_result.get("redirected"):
        risk_points += 5

    if page_result.get("forms_found", 0) > 0:
        risk_points += 20

    if page_result.get("iframe_count", 0) > 0:
        risk_points += min(page_result["iframe_count"] * 5, 15)

    if page_result.get("mixed_content"):
        risk_points += 15

    if page_result.get("external_scripts", 0) >= 5:
        risk_points += 10
    elif page_result.get("external_scripts", 0) >= 1:
        risk_points += 5

    risk_points += min(page_result.get("suspicious_keywords_count", 0) * 5, 25)

    score = max(0, 100 - risk_points)

    if risk_points >= 60:
        return {"risk": "HIGH", "score": score, "risk_points": risk_points}

    if risk_points >= 30:
        return {"risk": "MEDIUM", "score": score, "risk_points": risk_points}

    return {"risk": "LOW", "score": score, "risk_points": risk_points}
