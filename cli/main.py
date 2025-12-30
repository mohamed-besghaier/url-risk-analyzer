import argparse
from engine import domain_checks, tls_checks, page_checks, score, explain

def main():
    parser = argparse.ArgumentParser(prog="url-risk-analyzer",
                                     description= "Analyze URLs for potential security risks and explain why a URL is safe or unsafe.",
                                     usage='python -m cli.main url'
                                     )
    parser.add_argument("url", help="URL to analyze")
    args = parser.parse_args()
    url = args.url

    # Call engine functions
    domain_result = domain_checks.check_domain(url)
    tls_result = tls_checks.check_tls(url)
    page_result = page_checks.check_page(url)
    risk_score = score.calculate_score(domain_result, tls_result, page_result)
    explanation = explain.explain(
        {"domain": domain_result, "tls": tls_result, "page": page_result},
        risk_score
    )

    # Output
    print("Findings:")
    print(domain_result)
    print(tls_result)
    print(page_result)
    print(explanation)

if __name__ == "__main__":
    main()
