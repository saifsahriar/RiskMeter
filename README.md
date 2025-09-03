# Subdomain Risk Assessment Tool

A comprehensive command-line tool designed for bug bounty hunters and security researchers to assess the risk level of subdomains. The tool analyzes various security indicators and assigns risk scores from 0-100 to help prioritize security testing efforts.

## Overview

This tool probes subdomains and calculates risk scores based on multiple security indicators including environment keywords, exposed management interfaces, authentication boundaries, legacy technologies, and infrastructure hardening. Results are color-coded and can be exported for further analysis or visualization.

## Risk Scoring Methodology

The tool assigns risk scores from 0-100 based on evidence that a subdomain is either risky or hardened. Higher scores indicate higher priority targets for security testing.

### Positive Risk Indicators (Increase Score)

**Environment/Role Keywords (+20 points)**
- Detects development, staging, or administrative keywords in subdomain names
- Pattern: `/(^|[.-])(dev|staging|qa|uat|preprod|preview|test|sandbox|beta|old|legacy|v[0-9]+|feature|pr-\d+|internal|intranet|admin|portal|console|manage|cms|editor|dashboard)([.-]|$)/`
- Examples: `dev.example.com`, `admin-panel.example.com`, `staging-api.example.com`

**Non-CDN Exposure (+5 points)**
- Subdomains not behind Content Delivery Networks (CDN) like Cloudflare or Akamai
- Direct origin exposure usually means fewer safety nets and more direct access to infrastructure

**Edge of Authentication (+8 points)**
- First response returns authentication-required status codes (401/403/407/421/451) on non-marketing hosts
- Indicates presence of protected applications rather than static marketing pages

**Management/Observability Surfaces (+30 points)**
- Detection of DevOps and management tools in page titles, headers, or content
- Tools: `Jenkins|Grafana|Kibana|SonarQube|Harbor|Artifactory|Nexus|MinIO|Argo CD|Kubernetes|Traefik|Kong|Prometheus|OpenSearch|Elasticsearch|pgAdmin|phpMyAdmin|Superset|Metabase|Redash`

**Development Server Ports (+10 points)**
- Services running on common development ports: `3000, 3001, 5000, 8000, 8080, 8081, 8443, 9000, 9090, 5601, 9200, 15672, 2375`
- Note: This is a signal, not an assumption of specific services

**Legacy/Outlier Technology (+15 points)**
- Outdated or uncommon technologies that deviate from organizational norms
- Technologies: `ColdFusion|WebLogic|JBoss|Struts|Tomcat 7|GlassFish|Drupal 7|AEM 6.0–6.3|PHP 5.*|WordPress 4.*`

**Non-Indexed Content (+6 points)**
- Pages with `X-Robots-Tag: noindex` or meta noindex directives on non-marketing hosts
- Often indicates forgotten or administrative surfaces

**Fresh or Frequently Changing Content (+12 points)**
- Dynamic ETags or Last-Modified headers indicating frequent content changes
- New deployments often introduce new security vulnerabilities

**Leaky JavaScript (+12 points)**
- Client-side JavaScript referencing internal hostnames, GraphQL endpoints, cloud storage, or administrative panels
- Patterns include internal domains, `/graphql` endpoints, S3/Blob storage URLs

### Negative Risk Indicators (Decrease Score)

**Hardened Marketing Sites (-15 points each)**
- Subdomains behind CDNs (Cloudflare/Akamai) that appear to be marketing/CMS sites
- Indicators: `/wp-content/`, "Careers", "Blog", "Press" content
- 301/302 redirects to main site with identical fingerprints

## Installation

### Traditional Installation

**Prerequisites:**
- Python 3.7 or higher
- pip package manager

**Setup:**
```bash
# Clone or download the project
git clone <repository-url>
cd subdomain-recon

# Install dependencies
pip install -r requirements.txt

# Make script executable (Linux/macOS)
chmod +x risk_meter.py
```

### Docker Installation

**Prerequisites:**
- Docker
- Docker Compose (optional)

**Setup:**
```bash
# Clone or download the project
git clone <repository-url>
cd subdomain-recon

# Make run script executable
chmod +x run-docker.sh

# Create input/output directories
mkdir -p input output
```

## Usage

### Traditional Usage

**Basic scan:**
```bash
python3 risk_meter.py -f subdomains.txt
```

**Advanced options:**
```bash
# Custom thread count and timeout
python3 risk_meter.py -f subdomains.txt -t 30 --timeout 15

# Save results to JSON
python3 risk_meter.py -f subdomains.txt -o results.json

# Filter by minimum score
python3 risk_meter.py -f subdomains.txt --min-score 20

# Combined options
python3 risk_meter.py -f subdomains.txt -t 50 --timeout 10 -o high-risk-results.json --min-score 30
```

### Docker Usage

**Using the wrapper script (recommended):**
```bash
# Basic scan
./run-docker.sh -f subdomains.txt

# With custom options
./run-docker.sh -f subdomains.txt -o results.json -t 30 --timeout 15

# Filter high-risk targets only
./run-docker.sh -f subdomains.txt --min-score 50
```

**Manual Docker commands:**
```bash
# Build image
docker build -t subdomain-recon .

# Copy subdomains file to input directory
cp your-subdomains.txt input/subdomains.txt

# Run container
docker run --rm \
  -v $(pwd)/input:/app/input:ro \
  -v $(pwd)/output:/app/output:rw \
  subdomain-recon \
  -f /app/input/subdomains.txt -o /app/output/results.json
```

**Using Docker Compose:**
```bash
# Copy subdomains file
cp subdomains.txt input/

# Build and run
docker-compose up --build

# Run with custom parameters
docker-compose run --rm recon-tool \
  -f /app/input/subdomains.txt \
  -o /app/output/results.json \
  -t 30 --timeout 15
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file` | Input file containing subdomains (required) | - |
| `-o, --output` | Output JSON file for results | - |
| `-t, --threads` | Number of concurrent threads | 50 |
| `--timeout` | Request timeout in seconds | 10 |
| `--min-score` | Minimum score to display results | 0 |
| `-h, --help` | Show help message | - |

## Input Format

Create a text file with one subdomain per line:

```
admin.example.com
dev-api.example.com
staging.example.com
www.example.com
old-cms.example.com
jenkins.example.com
```

Lines starting with `#` are treated as comments and ignored.

## Output Format

### Terminal Output

Results are displayed with color coding:
- **Red/Bold**: High risk (50+ points)
- **Yellow/Bold**: Medium risk (30-49 points)
- **Cyan**: Low-medium risk (15-29 points)
- **Green**: Low risk (0-14 points)

Each result shows:
- Risk score and subdomain name
- IP address and HTTP status code
- Page title (if available)
- Port number (if non-standard)
- Detailed reasons for the assigned score

### JSON Output

When using the `-o` option, results are saved in JSON format containing:

```json
[
  {
    "subdomain": "admin.example.com",
    "ip": "192.168.1.100",
    "score": 65,
    "status_code": 200,
    "title": "Admin Dashboard - Jenkins",
    "port": 8080,
    "is_cdn": false,
    "is_cms": false,
    "reasons": [
      "Environment/Dev keyword in subdomain (+20)",
      "Management/DevOps tool detected (+30)",
      "Development port 8080 (+10)",
      "Not behind CDN (+5)"
    ],
    "headers": {...}
  }
]
```

## Common Use Cases

**Quick triage of large subdomain lists:**
```bash
# Focus on high-risk targets only
python3 risk_meter.py -f 1000-subdomains.txt --min-score 40 -o high-priority.json
```

**Development environment discovery:**
```bash
# Look for dev/staging environments
python3 risk_meter.py -f subdomains.txt | grep -i "dev\|staging\|test"
```

**Administrative interface hunting:**
```bash
# Find admin panels and management interfaces
python3 risk_meter.py -f subdomains.txt --min-score 25 | grep -i "admin\|manage\|console"
```

**Comprehensive security assessment:**
```bash
# Full analysis with detailed output
python3 risk_meter.py -f all-subdomains.txt -t 100 --timeout 20 -o comprehensive-results.json
```

## Performance Tuning

**For large subdomain lists (1000+):**
- Increase threads: `-t 100`
- Reduce timeout: `--timeout 5`
- Use minimum score filtering: `--min-score 15`

**For thorough analysis:**
- Lower thread count: `-t 20`
- Increase timeout: `--timeout 20`
- No score filtering to catch all results

**For quick reconnaissance:**
- High minimum score: `--min-score 40`
- Standard settings for speed vs accuracy balance

## Result Visualization

For better analysis of large result sets, use the included web-based dashboard:

1. **Generate results:** Run the tool with JSON output option
```bash
python3 risk_meter.py -f subdomains.txt -o results.json
```

2. **Open dashboard:** Open `visualizer.html` in any web browser

3. **Upload results:** Click "Upload Results JSON File" and select your `results.json`

4. **Analyze interactively:** Use the dashboard features:
   - Filter by risk level (High/Medium/Low)
   - Search specific subdomains
   - Set minimum score thresholds
   - Sort by different criteria
   - Export filtered results

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any systems they do not own.
