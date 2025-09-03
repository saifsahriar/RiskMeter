#!/usr/bin/env python3
"""
Subdomain Risk Assessment Tool for Bug Bounty
Analyzes subdomains and calculates risk scores based on various indicators
"""

import argparse
import asyncio
import aiohttp
import re
import sys
import time
import json
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor
import subprocess
import os

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SubdomainAnalyzer:
    def __init__(self, timeout=10, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.session = None
        self.results = []
        
        # Regex patterns for scoring
        self.env_pattern = re.compile(
            r'(^|[.-])(dev|staging|qa|uat|preprod|preview|test|sandbox|beta|old|legacy|v[0-9]+|feature|pr-\d+|internal|intranet|admin|portal|console|manage|cms|editor|dashboard)([.-]|$)',
            re.IGNORECASE
        )
        
        self.mgmt_pattern = re.compile(
            r'Jenkins|Grafana|Kibana|SonarQube|Harbor|Artifactory|Nexus|MinIO|Argo CD|Kubernetes|Traefik|Kong|Prometheus|OpenSearch|Elasticsearch|pgAdmin|phpMyAdmin|Superset|Metabase|Redash',
            re.IGNORECASE
        )
        
        self.outlier_tech_pattern = re.compile(
            r'ColdFusion|WebLogic|JBoss|Struts|Tomcat 7|GlassFish|Drupal 7|AEM 6\.[0-3]|PHP 5\.|WordPress 4\.',
            re.IGNORECASE
        )
        
        self.dev_ports = [3000, 3001, 5000, 8000, 8080, 8081, 8443, 9000, 9090, 5601, 9200, 15672, 2375]
        
        self.cdn_indicators = [
            'cloudflare', 'akamai', 'fastly', 'maxcdn', 'keycdn', 
            'cloudfront', 'azure', 'incapsula', 'sucuri'
        ]
        
        self.cms_indicators = [
            '/wp-content/', 'careers', 'blog', 'press', '/wp-admin/',
            '/wp-includes/', 'wordpress', 'drupal'
        ]

    async def init_session(self):
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            limit_per_host=10,
            ssl=False,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )

    async def close_session(self):
        if self.session:
            await self.session.close()

    def check_dns_resolution(self, domain):
        """Check if domain resolves and get IP"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    async def probe_subdomain(self, subdomain):
        """Main probing function for a subdomain"""
        subdomain = subdomain.strip()
        if not subdomain:
            return None
            
        # Check DNS resolution first
        ip = self.check_dns_resolution(subdomain)
        if not ip:
            return None
            
        result = {
            'subdomain': subdomain,
            'ip': ip,
            'score': 0,
            'reasons': [],
            'status_code': None,
            'title': '',
            'headers': {},
            'technologies': [],
            'is_cdn': False,
            'is_cms': False,
            'port': 80
        }
        
        # Try both HTTP and HTTPS
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            
            try:
                async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                    result['status_code'] = response.status
                    result['headers'] = dict(response.headers)
                    
                    # Get page content for analysis
                    try:
                        content = await response.text(encoding='utf-8', errors='ignore')
                        result['title'] = self.extract_title(content)
                        result['content'] = content[:5000]  # First 5KB for analysis
                    except:
                        result['content'] = ''
                    
                    # Successfully connected, break the loop
                    break
                    
            except Exception as e:
                continue
        
        # Try common dev ports if standard ports fail
        if result['status_code'] is None:
            for port in [8080, 8443, 9000]:
                try:
                    url = f"http://{subdomain}:{port}"
                    async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                        result['status_code'] = response.status
                        result['headers'] = dict(response.headers)
                        result['port'] = port
                        try:
                            content = await response.text(encoding='utf-8', errors='ignore')
                            result['title'] = self.extract_title(content)
                            result['content'] = content[:5000]
                        except:
                            result['content'] = ''
                        break
                except:
                    continue
        
        # Calculate risk score
        self.calculate_risk_score(result)
        
        return result

    def extract_title(self, content):
        """Extract title from HTML content"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()[:100]
        return ''

    def calculate_risk_score(self, result):
        """Calculate risk score based on various indicators"""
        score = 0
        reasons = []
        subdomain = result['subdomain']
        headers = result.get('headers', {})
        title = result.get('title', '')
        content = result.get('content', '')
        status_code = result.get('status_code')
        
        # Environment/role in name (+20)
        if self.env_pattern.search(subdomain):
            score += 20
            reasons.append("Environment/Dev keyword in subdomain (+20)")
        
        # Check for CDN
        is_cdn = self.is_behind_cdn(headers, subdomain)
        result['is_cdn'] = is_cdn
        
        # Non-CDN (+5)
        if not is_cdn:
            score += 5
            reasons.append("Not behind CDN (+5)")
        
        # Edge of auth status (+8)
        if status_code in [401, 403, 407, 421, 451]:
            if not self.looks_like_marketing(content, subdomain):
                score += 8
                reasons.append(f"Authentication required (HTTP {status_code}) (+8)")
        
        # Management/observability surfaces (+30)
        mgmt_content = title + ' ' + str(headers) + ' ' + content
        if self.mgmt_pattern.search(mgmt_content):
            score += 30
            reasons.append("Management/DevOps tool detected (+30)")
        
        # Dev server ports (+10)
        if result.get('port', 80) in self.dev_ports:
            score += 10
            reasons.append(f"Development port {result['port']} (+10)")
        
        # Outlier technology (+15)
        tech_content = title + ' ' + str(headers) + ' ' + content
        if self.outlier_tech_pattern.search(tech_content):
            score += 15
            reasons.append("Legacy/Outlier technology detected (+15)")
        
        # Non-indexed (+6)
        robots_header = headers.get('X-Robots-Tag', '').lower()
        if 'noindex' in robots_header or 'noindex' in content.lower():
            if not self.looks_like_marketing(content, subdomain):
                score += 6
                reasons.append("Non-indexed content (+6)")
        
        # Fresh or churning - check for dynamic ETags (+12)
        etag = headers.get('ETag', '')
        last_modified = headers.get('Last-Modified', '')
        if etag and ('W/' in etag or len(etag) > 20):
            score += 12
            reasons.append("Dynamic content/frequent changes (+12)")
        
        # Leaky JS (+12)
        if self.has_leaky_js(content):
            score += 12
            reasons.append("Leaky JavaScript detected (+12)")
        
        # Hardened/likely boring (-15 each)
        is_cms = self.looks_like_marketing(content, subdomain)
        result['is_cms'] = is_cms
        
        if is_cdn and is_cms:
            score -= 15
            reasons.append("Hardened marketing site behind CDN (-15)")
        
        # Check for redirect to main site
        if self.is_redirect_to_main(headers, subdomain):
            score -= 15
            reasons.append("Redirects to main site (-15)")
        
        result['score'] = max(0, min(100, score))  # Clamp between 0-100
        result['reasons'] = reasons

    def is_behind_cdn(self, headers, subdomain):
        """Check if subdomain is behind a CDN"""
        server = headers.get('Server', '').lower()
        cf_ray = headers.get('CF-Ray', '')
        x_served_by = headers.get('X-Served-By', '').lower()
        
        for cdn in self.cdn_indicators:
            if cdn in server or cdn in x_served_by:
                return True
        
        if cf_ray:  # Cloudflare
            return True
            
        return False

    def looks_like_marketing(self, content, subdomain):
        """Check if this looks like a marketing/CMS site"""
        content_lower = content.lower()
        subdomain_lower = subdomain.lower()
        
        # Check for CMS indicators
        for indicator in self.cms_indicators:
            if indicator in content_lower:
                return True
        
        # Check for marketing keywords
        marketing_keywords = [
            'about us', 'contact us', 'careers', 'blog', 'news', 
            'press', 'privacy policy', 'terms of service', 'products',
            'solutions', 'services', 'customers', 'partners'
        ]
        
        keyword_count = sum(1 for keyword in marketing_keywords if keyword in content_lower)
        
        return keyword_count >= 2

    def has_leaky_js(self, content):
        """Check for leaky JavaScript"""
        js_patterns = [
            r'https?://[a-zA-Z0-9.-]+\.(internal|local|dev|staging)',
            r'/graphql["\']',
            r'\.s3\.amazonaws\.com',
            r'\.blob\.core\.windows\.net',
            r'admin\.(.*?)\.(com|net|org)',
            r'api\.(.*?)\.internal'
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False

    def is_redirect_to_main(self, headers, subdomain):
        """Check if this redirects to main site"""
        location = headers.get('Location', '')
        if not location:
            return False
        
        # Extract main domain
        parts = subdomain.split('.')
        if len(parts) >= 2:
            main_domain = '.'.join(parts[-2:])
            return main_domain in location and location.count('.') <= subdomain.count('.')
        
        return False

    def get_risk_color(self, score):
        """Get color based on risk score"""
        if score >= 50:
            return Colors.RED + Colors.BOLD
        elif score >= 30:
            return Colors.YELLOW + Colors.BOLD
        elif score >= 15:
            return Colors.CYAN
        else:
            return Colors.GREEN

    async def analyze_subdomains(self, subdomains):
        """Analyze all subdomains"""
        print(f"{Colors.CYAN}[*] Starting analysis of {len(subdomains)} subdomains...{Colors.END}")
        
        await self.init_session()
        
        try:
            # Create semaphore to limit concurrent connections
            semaphore = asyncio.Semaphore(self.threads)
            
            async def analyze_with_semaphore(subdomain):
                async with semaphore:
                    return await self.probe_subdomain(subdomain)
            
            # Process all subdomains
            tasks = [analyze_with_semaphore(sub) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None results and exceptions
            self.results = [r for r in results if r and not isinstance(r, Exception) and r.get('status_code')]
            
        finally:
            await self.close_session()

    def print_results(self):
        """Print sorted results with colors"""
        if not self.results:
            print(f"{Colors.RED}[!] No accessible subdomains found{Colors.END}")
            return
        
        # Sort by score (highest first)
        sorted_results = sorted(self.results, key=lambda x: x['score'], reverse=True)
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}SUBDOMAIN RISK ASSESSMENT RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")
        
        high_risk = [r for r in sorted_results if r['score'] >= 50]
        medium_risk = [r for r in sorted_results if 30 <= r['score'] < 50]
        low_risk = [r for r in sorted_results if r['score'] < 30]
        
        print(f"{Colors.RED}[HIGH RISK] {len(high_risk)} subdomains{Colors.END}")
        print(f"{Colors.YELLOW}[MEDIUM RISK] {len(medium_risk)} subdomains{Colors.END}")
        print(f"{Colors.GREEN}[LOW RISK] {len(low_risk)} subdomains{Colors.END}\n")
        
        for result in sorted_results:
            self.print_subdomain_result(result)
    
    def print_subdomain_result(self, result):
        """Print individual subdomain result"""
        score = result['score']
        color = self.get_risk_color(score)
        
        print(f"{color}[{score:2d}] {result['subdomain']}{Colors.END}")
        print(f"     IP: {result['ip']} | Status: {result.get('status_code', 'N/A')}")
        
        if result.get('title'):
            print(f"     Title: {result['title']}")
        
        if result.get('port', 80) != 80:
            print(f"     Port: {result['port']}")
        
        if result.get('reasons'):
            for reason in result['reasons']:
                print(f"     {Colors.WHITE}> {reason}{Colors.END}")
        
        print()

    def save_json_output(self, filename):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.END}")

def load_subdomains(filename):
    """Load subdomains from file"""
    subdomains = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if subdomain and not subdomain.startswith('#'):
                    # Remove protocol if present
                    if '://' in subdomain:
                        subdomain = subdomain.split('://', 1)[1]
                    # Remove path if present
                    subdomain = subdomain.split('/', 1)[0]
                    # Remove port if present
                    subdomain = subdomain.split(':', 1)[0]
                    
                    if subdomain:
                        subdomains.append(subdomain)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] File {filename} not found{Colors.END}")
        sys.exit(1)
    
    return list(set(subdomains))  # Remove duplicates

def main():
    parser = argparse.ArgumentParser(
        description='Subdomain Risk Assessment Tool for Bug Bounty',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon_tool.py -f subdomains.txt
  python3 recon_tool.py -f subdomains.txt -t 20 -o results.json
  python3 recon_tool.py -f subdomains.txt --timeout 15 --threads 30
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='File containing subdomains (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('--min-score', type=int, default=0, help='Minimum score to display (default: 0)')
    
    args = parser.parse_args()
    
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("Subdomain Risk Assessment Tool")
    print("=============================")
    print(f"{Colors.END}")
    
    # Load subdomains
    subdomains = load_subdomains(args.file)
    print(f"{Colors.GREEN}[+] Loaded {len(subdomains)} unique subdomains{Colors.END}")
    
    if not subdomains:
        print(f"{Colors.RED}[!] No subdomains found in file{Colors.END}")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = SubdomainAnalyzer(timeout=args.timeout, threads=args.threads)
    
    # Run analysis
    start_time = time.time()
    
    try:
        asyncio.run(analyzer.analyze_subdomains(subdomains))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        sys.exit(1)
    
    end_time = time.time()
    
    # Filter by minimum score
    if args.min_score > 0:
        analyzer.results = [r for r in analyzer.results if r['score'] >= args.min_score]
    
    # Print results
    analyzer.print_results()
    
    print(f"\n{Colors.CYAN}[*] Analysis completed in {end_time - start_time:.2f} seconds{Colors.END}")
    print(f"{Colors.CYAN}[*] Found {len(analyzer.results)} accessible subdomains{Colors.END}")
    
    # Save JSON output if requested
    if args.output:
        analyzer.save_json_output(args.output)

if __name__ == "__main__":
    main()