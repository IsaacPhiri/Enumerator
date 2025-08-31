import socket
import ssl
import ftplib
import paramiko
import json
from datetime import datetime
import requests
from urllib.parse import urlparse

class ServiceEnumerator:
    def __init__(self):
        self.timeout = 5

    def enumerate_services(self, target, ports=None):
        """
        Perform comprehensive service enumeration
        Args:
            target: IP address or hostname
            ports: List of ports to enumerate (if None, uses common ports)
        Returns:
            dict: Enumeration results
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'services': []
        }

        for port in ports:
            try:
                service_info = self.enumerate_port(target, port)
                if service_info:
                    results['services'].append(service_info)
            except Exception as e:
                results['services'].append({
                    'port': port,
                    'error': str(e)
                })

        return results

    def enumerate_port(self, target, port):
        """Enumerate a specific port"""
        service_info = {
            'port': port,
            'state': 'unknown',
            'service': 'unknown',
            'banner': '',
            'version': '',
            'vulnerabilities': []
        }

        try:
            # Basic TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))

            if result == 0:
                service_info['state'] = 'open'

                # Try to identify service
                if port == 21:
                    service_info.update(self.enumerate_ftp(target, port))
                elif port == 22:
                    service_info.update(self.enumerate_ssh(target, port))
                elif port in [80, 443, 8080]:
                    service_info.update(self.enumerate_http(target, port))
                elif port == 25:
                    service_info.update(self.enumerate_smtp(target, port))
                elif port == 110:
                    service_info.update(self.enumerate_pop3(target, port))
                elif port == 143:
                    service_info.update(self.enumerate_imap(target, port))
                elif port == 3306:
                    service_info.update(self.enumerate_mysql(target, port))
                else:
                    # Generic banner grabbing
                    service_info.update(self.grab_banner(target, port))

            sock.close()

        except Exception as e:
            service_info['error'] = str(e)

        return service_info

    def grab_banner(self, target, port):
        """Generic banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send common probes
            probes = [b'', b'HEAD / HTTP/1.0\r\n\r\n', b'HELP\r\n', b'QUIT\r\n']

            banner = ''
            for probe in probes:
                try:
                    sock.send(probe)
                    response = sock.recv(1024)
                    if response:
                        banner = response.decode('utf-8', errors='ignore').strip()
                        break
                except:
                    continue

            sock.close()

            return {
                'banner': banner,
                'service': self.identify_service_from_banner(banner, port)
            }

        except Exception as e:
            return {'banner': '', 'service': 'unknown', 'error': str(e)}

    def enumerate_ftp(self, target, port):
        """FTP enumeration"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=self.timeout)
            banner = ftp.getwelcome()
            ftp.quit()

            return {
                'service': 'ftp',
                'banner': banner,
                'version': self.extract_version_from_banner(banner),
                'anonymous_login': self.check_anonymous_ftp(target, port)
            }
        except Exception as e:
            return {'service': 'ftp', 'error': str(e)}

    def enumerate_ssh(self, target, port):
        """SSH enumeration"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # SSH banner is sent immediately upon connection
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return {
                'service': 'ssh',
                'banner': banner,
                'version': self.extract_version_from_banner(banner)
            }
        except Exception as e:
            return {'service': 'ssh', 'error': str(e)}

    def enumerate_http(self, target, port):
        """HTTP/HTTPS enumeration"""
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}/"

            # Try to get server headers
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)

            server_info = {
                'service': 'http' if port != 443 else 'https',
                'banner': f"HTTP/{response.raw.version / 10} {response.status_code}",
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'content_type': response.headers.get('Content-Type', ''),
                'technologies': self.detect_web_technologies(response)
            }

            return server_info

        except Exception as e:
            return {'service': 'http', 'error': str(e)}

    def enumerate_smtp(self, target, port):
        """SMTP enumeration"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # SMTP banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

            # Try EHLO command
            sock.send(b'EHLO test\r\n')
            ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore')

            sock.close()

            return {
                'service': 'smtp',
                'banner': banner,
                'ehlo_response': ehlo_response,
                'version': self.extract_version_from_banner(banner)
            }
        except Exception as e:
            return {'service': 'smtp', 'error': str(e)}

    def enumerate_pop3(self, target, port):
        """POP3 enumeration"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return {
                'service': 'pop3',
                'banner': banner,
                'version': self.extract_version_from_banner(banner)
            }
        except Exception as e:
            return {'service': 'pop3', 'error': str(e)}

    def enumerate_imap(self, target, port):
        """IMAP enumeration"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return {
                'service': 'imap',
                'banner': banner,
                'version': self.extract_version_from_banner(banner)
            }
        except Exception as e:
            return {'service': 'imap', 'error': str(e)}

    def enumerate_mysql(self, target, port):
        """MySQL enumeration"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # MySQL handshake packet
            handshake = sock.recv(1024)
            sock.close()

            return {
                'service': 'mysql',
                'banner': handshake.hex() if handshake else '',
                'version': self.extract_mysql_version(handshake) if handshake else ''
            }
        except Exception as e:
            return {'service': 'mysql', 'error': str(e)}

    def check_anonymous_ftp(self, target, port):
        """Check for anonymous FTP login"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=self.timeout)
            ftp.login('anonymous', 'anonymous@')
            ftp.quit()
            return True
        except:
            return False

    def detect_web_technologies(self, response):
        """Detect web technologies from HTTP response"""
        technologies = []

        headers = response.headers
        content = response.text.lower()

        # Check for common technologies
        tech_checks = {
            'PHP': ['php', 'x-powered-by.*php'],
            'ASP.NET': ['asp.net', 'x-aspnet-version'],
            'JSP': ['jsp', 'javaserver'],
            'Node.js': ['x-powered-by.*node'],
            'Apache': ['apache', 'server.*apache'],
            'Nginx': ['nginx', 'server.*nginx'],
            'IIS': ['microsoft-iis', 'server.*iis'],
            'Tomcat': ['tomcat', 'server.*tomcat'],
            'WordPress': ['wp-content', 'wordpress'],
            'Joomla': ['joomla', 'com_joomla'],
            'Drupal': ['drupal', 'sites/all']
        }

        for tech, patterns in tech_checks.items():
            for pattern in patterns:
                if pattern in content or any(pattern in str(headers).lower() for header in headers):
                    technologies.append(tech)
                    break

        return list(set(technologies))

    def identify_service_from_banner(self, banner, port):
        """Identify service from banner"""
        banner_lower = banner.lower()

        service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'rdp',
            5900: 'vnc',
            8080: 'http-proxy'
        }

        # Check banner content
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'http' in banner_lower:
            return 'http'
        elif 'smtp' in banner_lower:
            return 'smtp'
        elif 'pop3' in banner_lower:
            return 'pop3'
        elif 'imap' in banner_lower:
            return 'imap'
        elif 'mysql' in banner_lower:
            return 'mysql'

        return service_map.get(port, 'unknown')

    def extract_version_from_banner(self, banner):
        """Extract version information from banner"""
        import re

        # Common version patterns
        patterns = [
            r'version\s+([\d.]+)',
            r'v([\d.]+)',
            r'([\d]+\.[\d]+(?:\.[\d]+)*)',
            r'OpenSSH_([\d.]+)',
            r'Apache/([\d.]+)',
            r'nginx/([\d.]+)',
            r'IIS/([\d.]+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return ''

    def extract_mysql_version(self, handshake):
        """Extract MySQL version from handshake packet"""
        try:
            # MySQL handshake packet format
            if len(handshake) > 5:
                version_end = handshake.find(b'\x00', 5)
                if version_end > 5:
                    version = handshake[5:version_end].decode('utf-8', errors='ignore')
                    return version
        except:
            pass
        return ''

def format_service_results(results):
    """Format service enumeration results for display"""
    if 'error' in results:
        return f"Error: {results['error']}"

    output = f"Service Enumeration Results for {results['target']}\n"
    output += f"Scan Time: {results['scan_time']}\n\n"

    for service in results.get('services', []):
        output += f"Port {service['port']}: {service.get('state', 'unknown').upper()}\n"

        if service.get('service') != 'unknown':
            output += f"  Service: {service['service']}\n"

        if service.get('banner'):
            output += f"  Banner: {service['banner'][:100]}{'...' if len(service['banner']) > 100 else ''}\n"

        if service.get('version'):
            output += f"  Version: {service['version']}\n"

        if service.get('server'):
            output += f"  Server: {service['server']}\n"

        if service.get('technologies'):
            output += f"  Technologies: {', '.join(service['technologies'])}\n"

        if service.get('anonymous_login') is True:
            output += f"  Anonymous Login: ALLOWED\n"

        if service.get('error'):
            output += f"  Error: {service['error']}\n"

        output += "\n"

    return output