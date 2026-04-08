# CVEIntel

CLI tool that determines whether specific CVEs have been patched across Amazon Linux releases. It cross-references the Amazon Linux Security Center (ALAS), uses a configurable LLM backend to interpret patch status, and generates audience-specific reports.

## Features

- Check CVE patch status across Amazon Linux 1, AL2, and AL2023
- Flexible input: CLI arguments, CSV/text files, or ECR image scan results
- Supports both basic and enhanced (Inspector) ECR scanning
- Audience-specific reports: developer (technical), business (executive summary), or both
- Business reports include CVE descriptions, impacted components, severity, and advisory links
- Developer reports include patch status per release, affected packages, fix versions, and remediation commands
- Multiple output targets: terminal (color-coded), file (JSON/text), or S3
- Configurable AI backend: OpenAI-compatible API, AWS Bedrock, or local LLM

## Installation

```bash
# Clone and install
git clone https://github.com/roshk8s/CVEIntel.git
cd CVEIntel
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## AI Provider Configuration

Copy `.env.example` to `.env` and configure your preferred AI provider:

### OpenAI-compatible API
```
CVEINTEL_PROVIDER=openai
CVEINTEL_API_KEY=sk-...
CVEINTEL_MODEL=gpt-4
```

### AWS Bedrock

For newer models (e.g., Claude Sonnet), use the cross-region inference profile format:
```
CVEINTEL_PROVIDER=bedrock
CVEINTEL_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0
AWS_DEFAULT_REGION=us-east-1
```

For older models that support direct invocation:
```
CVEINTEL_PROVIDER=bedrock
CVEINTEL_MODEL=anthropic.claude-3-haiku-20240307-v1:0
AWS_DEFAULT_REGION=us-east-1
```

### Local LLM
```
CVEINTEL_PROVIDER=local
CVEINTEL_LOCAL_ENDPOINT=http://localhost:8080/v1
CVEINTEL_MODEL=my-model
```

## Usage

```bash
# Check a single CVE
cveintel check CVE-2023-12345

# Check multiple CVEs (space or comma separated)
cveintel check CVE-2023-12345 CVE-2024-9999
cveintel check CVE-2023-12345,CVE-2024-9999

# Check CVEs from a file (CSV or one-per-line)
cveintel check --file cves.csv

# Check CVEs from an ECR image (supports both URI and ARN formats)
cveintel check --ecr 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
cveintel check --ecr arn:aws:ecr:us-east-1:123456789012:repository/myapp:latest

# Business stakeholder report (includes descriptions, impact, severity, advisory links)
cveintel check CVE-2023-12345 --audience business

# Consolidated report (developer + business in one output)
cveintel check CVE-2023-12345 --audience both

# Output to file as JSON
cveintel check CVE-2023-12345 --format json -o report.json

# Upload to S3
cveintel check CVE-2023-12345 --s3 s3://my-bucket/reports/report.json

# Override AI provider via CLI
cveintel check CVE-2023-12345 --provider bedrock

# See all options
cveintel check --help
```

### Report Audiences

- `developer` (default) — Patch status per release, affected packages with versions, remediation commands, and ALAS advisory links
- `business` — Plain-language CVE description, impacted components, severity, remediation status, and advisory links
- `both` — Consolidated report with both sections

### ECR Integration

The `--ecr` flag accepts ECR image URIs (what you copy from the ECR console or Docker commands) and supports both basic and enhanced (Inspector) scanning:

```bash
cveintel check --ecr 123456789012.dkr.ecr.eu-west-1.amazonaws.com/myrepo:mytag
```

Requires AWS credentials with `ecr:DescribeImageScanFindings` permission.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Project Structure

```
src/cveintel/
├── cli.py              # Click-based CLI layer
├── __main__.py         # python -m cveintel support
└── core/
    ├── analyzer.py     # LLM-based advisory analysis
    ├── ai_provider.py  # AI provider registry (OpenAI, Bedrock, local)
    ├── config.py       # Environment-based configuration
    ├── ecr_scanner.py  # ECR scan findings retrieval
    ├── exceptions.py   # Error hierarchy
    ├── fetcher.py      # ALAS advisory fetching
    ├── input_parser.py # CVE validation and file parsing
    ├── models.py       # Data models
    ├── output_handler.py   # Terminal, file, S3 output
    └── report_generator.py # Developer/business report generation
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass with `pytest`
5. Submit a pull request

## License

MIT
