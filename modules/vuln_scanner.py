import requests
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
import re

class VulnerabilityScanner:
    def __init__(self):
        self.timeout = 10
        self.vulnerabilities = []

    def scan_vulnerabilities(self, target, scan_type='web'):
        """
        Perform vulnerability scanning
        Args:
            target: Target to scan (IP, domain, or URL)
            scan_type: Type of scan (web, network, service)
        Returns:
            dict: Vulnerability scan results
        """
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'scan_type': scan_type,
            'vulnerabilities': [],
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        try:
            if scan_type == 'web':
                results['vulnerabilities'] = self._scan_web_vulnerabilities(target)
            elif scan_type == 'network':
                results['vulnerabilities'] = self._scan_network_vulnerabilities(target)
            elif scan_type == 'service':
                results['vulnerabilities'] = self._scan_service_vulnerabilities(target)

            # Count severities
            for vuln in results['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                if severity in results['severity_counts']:
                    results['severity_counts'][severity] += 1

        except Exception as e:
            results['error'] = str(e)

        return results

    def _scan_web_vulnerabilities(self, target):
        """Scan for web-specific vulnerabilities"""
        vulnerabilities = []

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        try:
            # Basic web server info gathering
            response = requests.get(target, timeout=self.timeout, verify=False, allow_redirects=True)

            # Check for common web vulnerabilities
            vulnerabilities.extend(self._check_common_web_vulns(target, response))

            # Check for specific CMS vulnerabilities
            if self._detect_wordpress(target):
                vulnerabilities.extend(self._check_wordpress_vulns(target))

            if self._detect_joomla(target):
                vulnerabilities.extend(self._check_joomla_vulns(target))

            if self._detect_drupal(target):
                vulnerabilities.extend(self._check_drupal_vulns(target))

        except Exception as e:
            vulnerabilities.append({
                'title': 'Web Scan Error',
                'description': f'Failed to scan web vulnerabilities: {str(e)}',
                'severity': 'info',
                'cve': '',
                'url': target
            })

        return vulnerabilities

    def _check_common_web_vulns(self, target, response):
        """Check for common web vulnerabilities"""
        vulnerabilities = []

        headers = response.headers
        content = response.text.lower()

        # Check for missing security headers
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]

        for header in security_headers:
            if header not in headers:
                vulnerabilities.append({
                    'title': f'Missing Security Header: {header}',
                    'description': f'The server is missing the {header} security header, which could leave it vulnerable to various attacks.',
                    'severity': 'medium',
                    'cve': '',
                    'url': target
                })

        # Check for directory listing
        if 'index of' in content and 'parent directory' in content:
            vulnerabilities.append({
                'title': 'Directory Listing Enabled',
                'description': 'Directory listing is enabled, which could expose sensitive files and folder structure.',
                'severity': 'medium',
                'cve': '',
                'url': target
            })

        # Check for outdated server software
        server = headers.get('Server', '')
        if server:
            if 'apache/2.2' in server.lower() or 'apache/2.4.1' in server.lower():
                vulnerabilities.append({
                    'title': 'Outdated Apache Server',
                    'description': f'Server is running {server} which may have known vulnerabilities.',
                    'severity': 'high',
                    'cve': 'Multiple CVEs',
                    'url': target
                })

        # Check for exposed admin panels
        admin_paths = ['/admin', '/admin/', '/administrator', '/wp-admin', '/login', '/signin']
        for path in admin_paths:
            try:
                admin_url = urljoin(target, path)
                admin_response = requests.get(admin_url, timeout=5, verify=False)
                if admin_response.status_code == 200:
                    vulnerabilities.append({
                        'title': 'Exposed Admin Panel',
                        'description': f'Admin panel found at {path}',
                        'severity': 'low',
                        'cve': '',
                        'url': admin_url
                    })
            except:
                pass

        return vulnerabilities

    def _detect_wordpress(self, target):
        """Detect if target is running WordPress"""
        try:
            wp_paths = ['/wp-admin', '/wp-content', '/wp-includes']
            for path in wp_paths:
                response = requests.get(urljoin(target, path), timeout=5, verify=False)
                if response.status_code == 200:
                    return True
            return False
        except:
            return False

    def _detect_joomla(self, target):
        """Detect if target is running Joomla"""
        try:
            joomla_paths = ['/administrator', '/components/com_content']
            for path in joomla_paths:
                response = requests.get(urljoin(target, path), timeout=5, verify=False)
                if response.status_code == 200:
                    return True
            return False
        except:
            return False

    def _detect_drupal(self, target):
        """Detect if target is running Drupal"""
        try:
            drupal_paths = ['/user/login', '/sites/default']
            for path in drupal_paths:
                response = requests.get(urljoin(target, path), timeout=5, verify=False)
                if response.status_code == 200:
                    return True
            return False
        except:
            return False

    def _check_wordpress_vulns(self, target):
        """Check for WordPress-specific vulnerabilities"""
        vulnerabilities = []

        # Check for common WordPress vulnerabilities
        vuln_checks = [
            {
                'path': '/wp-admin/admin-ajax.php',
                'title': 'WordPress AJAX Endpoint Exposed',
                'severity': 'low'
            },
            {
                'path': '/wp-json/wp/v2/users',
                'title': 'WordPress REST API User Enumeration',
                'severity': 'medium'
            },
            {
                'path': '/xmlrpc.php',
                'title': 'WordPress XML-RPC Enabled',
                'severity': 'medium'
            }
        ]

        for check in vuln_checks:
            try:
                response = requests.get(urljoin(target, check['path']), timeout=5, verify=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'title': check['title'],
                        'description': f'WordPress vulnerability found at {check["path"]}',
                        'severity': check['severity'],
                        'cve': '',
                        'url': urljoin(target, check['path'])
                    })
            except:
                pass

        return vulnerabilities

    def _check_joomla_vulns(self, target):
        """Check for Joomla-specific vulnerabilities"""
        vulnerabilities = []

        # Check for Joomla admin access
        try:
            response = requests.get(urljoin(target, '/administrator'), timeout=5, verify=False)
            if response.status_code == 200:
                vulnerabilities.append({
                    'title': 'Joomla Admin Panel Accessible',
                    'description': 'Joomla administrator panel is accessible without authentication',
                    'severity': 'high',
                    'cve': '',
                    'url': urljoin(target, '/administrator')
                })
        except:
            pass

        return vulnerabilities

    def _check_drupal_vulns(self, target):
        """Check for Drupal-specific vulnerabilities"""
        vulnerabilities = []

        # Check for Drupal user enumeration
        try:
            response = requests.get(urljoin(target, '/user/1'), timeout=5, verify=False)
            if response.status_code == 200:
                vulnerabilities.append({
                    'title': 'Drupal User Enumeration',
                    'description': 'User enumeration is possible in Drupal',
                    'severity': 'low',
                    'cve': '',
                    'url': urljoin(target, '/user/1')
                })
        except:
            pass

        return vulnerabilities

    def _scan_network_vulnerabilities(self, target):
        """Scan for network-level vulnerabilities"""
        vulnerabilities = []

        # This would typically use tools like OpenVAS, Nessus, etc.
        # For now, we'll do basic checks

        # Check for common open ports that might indicate vulnerabilities
        common_vuln_ports = {
            21: {'service': 'FTP', 'issue': 'FTP service may allow anonymous access'},
            23: {'service': 'Telnet', 'issue': 'Telnet transmits data in clear text'},
            25: {'service': 'SMTP', 'issue': 'SMTP may be vulnerable to relay attacks'},
            53: {'service': 'DNS', 'issue': 'DNS server may be vulnerable to cache poisoning'},
            139: {'service': 'NetBIOS', 'issue': 'NetBIOS may expose sensitive information'},
            445: {'service': 'SMB', 'issue': 'SMB may be vulnerable to eternalblue'},
            3389: {'service': 'RDP', 'issue': 'RDP may be vulnerable to bluekeep'},
            5900: {'service': 'VNC', 'issue': 'VNC may transmit credentials in clear text'}
        }

        # Note: In a real implementation, you'd check if these ports are actually open
        # For now, we'll just list potential issues

        for port, info in common_vuln_ports.items():
            vulnerabilities.append({
                'title': f'Potential {info["service"]} Vulnerability',
                'description': info['issue'],
                'severity': 'medium',
                'cve': '',
                'url': f'{target}:{port}'
            })

        return vulnerabilities

    def _scan_service_vulnerabilities(self, target):
        """Scan for service-specific vulnerabilities"""
        vulnerabilities = []

        # This would check for outdated service versions, default credentials, etc.
        # For demonstration, we'll add some generic service checks

        vulnerabilities.append({
            'title': 'Service Version Check Needed',
            'description': 'Manual verification of service versions is recommended',
            'severity': 'info',
            'cve': '',
            'url': target
        })

        return vulnerabilities

def format_vuln_results(results):
    """Format vulnerability scan results for display"""
    if 'error' in results:
        return f"Error: {results['error']}"

    output = f"Vulnerability Scan Results for {results['target']}\n"
    output += f"Scan Time: {results['scan_time']}\n"
    output += f"Scan Type: {results['scan_type']}\n\n"

    vulnerabilities = results.get('vulnerabilities', [])
    severity_counts = results.get('severity_counts', {})

    output += f"Summary:\n"
    output += f"  Total Vulnerabilities: {len(vulnerabilities)}\n"
    for severity, count in severity_counts.items():
        if count > 0:
            output += f"  {severity.capitalize()}: {count}\n"
    output += "\n"

    if vulnerabilities:
        output += f"Detailed Findings:\n"
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

        for i, vuln in enumerate(sorted_vulns, 1):
            output += f"{i}. [{vuln.get('severity', 'info').upper()}] {vuln['title']}\n"
            output += f"   Description: {vuln.get('description', 'N/A')}\n"
            if vuln.get('cve'):
                output += f"   CVE: {vuln['cve']}\n"
            output += f"   URL: {vuln.get('url', 'N/A')}\n\n"

    if not vulnerabilities:
        output += "No vulnerabilities found.\n"

    return output