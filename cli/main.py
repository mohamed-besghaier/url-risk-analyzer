import argparse
import validators
from engine import domain_checks, tls_checks, page_checks, score, explain
from tabulate import tabulate

def print_banner():
    print("""
URL Risk Analyzer
=================
Analyze URLs for security risks
""")

def print_dict_table (d) :
    table = [[k, v] for k, v in d.items()]
    print(tabulate(table, tablefmt="fancy_grid"))

def main():
    print_banner()
    parser = argparse.ArgumentParser(prog="url-risk-analyzer",
                                     description= "Analyze URLs for potential security risks and explain why a URL is safe or unsafe.",
                                     usage='python -m cli.main url'
                                     )
    parser.add_argument("url",
                        help="The full URL to analyze. Example formats: http://www.example.com or https://example.com")
    args = parser.parse_args()
    url = args.url

    if not validators.url(url):
        parser.error(f"Invalid URL: {url}")

    try:
        domain_result = domain_checks.check_domain(url)
    except Exception:
        parser.error(f"Domain could not be resolved: {url}")
    
    try :
        page_result = page_checks.check_page(url)
    except Exception:
        parser.error(f"Unable to reach URL: {url}")
        
    tls_result = tls_checks.check_tls(url)
    
    risk_score = score.calculate_score(domain_result, tls_result, page_result)
    explanation = explain.explain(
        {"domain": domain_result, "tls": tls_result, "page": page_result},
        risk_score
    )

    # Output
    print("Findings:")
    print_dict_table(domain_result)
    print_dict_table(tls_result)
    print_dict_table(page_result)
    print(explanation)

if __name__ == "__main__":
    main()
