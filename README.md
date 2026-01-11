# URL Risk Analyzer

A command-line security analysis tool that evaluates URLs for potential risks and provides human-readable explanations of findings. The analyzer checks domain reputation, TLS/SSL certificates, and page content to assign a risk score (LOW, MEDIUM, or HIGH).

## Features

- **Domain Analysis**: Validates domain age, registrar reputation, TLD safety, and checks for typosquatting
- **TLS/SSL Verification**: Confirms valid SSL certificates and secure connections
- **Page Content Inspection**: Detects login forms, external scripts, mixed content, and other security indicators
- **Risk Scoring**: Calculates overall risk level based on multiple factors
- **Detailed Explanations**: Provides clear, human-readable reasoning for risk assessments

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd url-risk-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Analyze a URL from the command line:

```bash
python -m cli.main https://example.com
```

### Example Output
The tool will display:
- Domain check results
- TLS/SSL certificate validation
- Page content analysis
- Overall risk score (LOW / MEDIUM / HIGH)
- Explanation of findings

## Project Structure

```
url-risk-analyzer/
├── cli/                    # Command-line interface
│   ├── __init__.py
│   └── main.py            # CLI entry point
├── engine/                # Core analysis engine
│   ├── domain_checks.py   # Domain reputation and age analysis
│   ├── tls_checks.py      # SSL/TLS certificate validation
│   ├── page_checks.py     # Web page content inspection
│   ├── score.py           # Risk scoring algorithm
│   └── explain.py         # Risk explanation generation
└── README.md              # This file
```

## How It Works

1. **URL Validation**: Verifies the provided URL format
2. **Domain Analysis**: Checks registrar reputation, domain age, and TLD safety
3. **TLS Verification**: Validates SSL certificate and secure connection
4. **Page Analysis**: Scans page content for security indicators
5. **Scoring**: Calculates risk score based on all findings
6. **Explanation**: Generates human-readable summary of results