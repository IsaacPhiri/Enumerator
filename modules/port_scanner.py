import nmap
import json
import socket
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.nm = None
        self.nmap_available = False
        try:
            self.nm = nmap.PortScanner()
            self.nmap_available = True
        except Exception as e:
            print(f"Nmap not available, falling back to socket scanning: {e}")
            self.nmap_available = False

    def socket_scan_ports(self, target, ports_list):
        """Fallback socket-based port scanning"""
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'command_line': f'socket scan on {target}',
            'scan_info': {'method': 'socket', 'ports_scanned': len(ports_list)},
            'hosts': [{
                'host': target,
                'hostname': target,
                'state': 'up',
                'protocols': [{
                    'protocol': 'tcp',
                    'ports': []
                }]
            }]
        }

        print(f"Starting socket-based port scan on {target} with {len(ports_list)} ports")

        for port in ports_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    port_info = {
                        'port': port,
                        'state': 'open',
                        'service': self.get_service_name(port),
                        'version': '',
                        'product': '',
                        'extrainfo': ''
                    }
                    results['hosts'][0]['protocols'][0]['ports'].append(port_info)
                sock.close()
            except:
                pass

        return results

    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 135: 'rpc',
            139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb',
            993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3306: 'mysql',
            3389: 'rdp', 5900: 'vnc', 8080: 'http-proxy'
        }
        return services.get(port, 'unknown')

    def scan_ports(self, target, ports='1-65535', arguments='-v -sS -O'):
        """
        Perform comprehensive port scanning with nmap fallback to socket scanning
        Args:
            target: IP address or hostname
            ports: Port range to scan (default: all ports)
            arguments: Nmap arguments
        Returns:
            dict: Scan results
        """
        try:
            # Try nmap first if available
            if self.nmap_available and self.nm:
                print(f"Starting nmap port scan on {target} with ports {ports}")
                self.nm.scan(target, ports=ports, arguments=arguments)

                results = {
                    'target': target,
                    'scan_time': datetime.now().isoformat(),
                    'command_line': self.nm.command_line(),
                    'scan_info': self.nm.scaninfo(),
                    'hosts': []
                }

                # Process results for each host
                for host in self.nm.all_hosts():
                    host_info = {
                        'host': host,
                        'hostname': self.nm[host].hostname(),
                        'state': self.nm[host].state(),
                        'protocols': []
                    }

                    # Get protocols (tcp, udp, etc.)
                    for proto in self.nm[host].all_protocols():
                        protocol_info = {
                            'protocol': proto,
                            'ports': []
                        }

                        # Get port information
                        lport = self.nm[host][proto].keys()
                        sorted_ports = sorted(lport)

                        for port in sorted_ports:
                            port_info = {
                                'port': port,
                                'state': self.nm[host][proto][port]['state'],
                                'service': self.nm[host][proto][port]['name'],
                                'version': self.nm[host][proto][port].get('version', ''),
                                'product': self.nm[host][proto][port].get('product', ''),
                                'extrainfo': self.nm[host][proto][port].get('extrainfo', '')
                            }
                            protocol_info['ports'].append(port_info)

                        host_info['protocols'].append(protocol_info)

                    # Add OS detection if available
                    if 'osmatch' in self.nm[host]:
                        host_info['os_detection'] = self.nm[host]['osmatch']

                    results['hosts'].append(host_info)

                return results

            else:
                # Fallback to socket scanning
                print("Nmap not available, using socket-based scanning")
                if ',' in ports:
                    # List of ports
                    ports_list = [int(p.strip()) for p in ports.split(',')]
                elif '-' in ports:
                    # Port range
                    start, end = ports.split('-')
                    ports_list = list(range(int(start), int(end) + 1))
                else:
                    # Single port
                    ports_list = [int(ports)]

                return self.socket_scan_ports(target, ports_list)

        except Exception as e:
            # If nmap fails, try socket scanning as fallback
            if self.nmap_available and "nmap program was not found" in str(e):
                print(f"Nmap failed: {e}, falling back to socket scanning")
                try:
                    if ',' in ports:
                        ports_list = [int(p.strip()) for p in ports.split(',')]
                    elif '-' in ports:
                        start, end = ports.split('-')
                        ports_list = list(range(int(start), int(end) + 1))
                    else:
                        ports_list = [int(ports)]

                    return self.socket_scan_ports(target, ports_list)
                except Exception as socket_error:
                    return {
                        'error': f'Both nmap and socket scanning failed: {str(socket_error)}',
                        'target': target,
                        'scan_time': datetime.now().isoformat()
                    }
            else:
                return {
                    'error': f'Port scan failed: {str(e)}',
                    'target': target,
                    'scan_time': datetime.now().isoformat()
                }

    def quick_scan(self, target):
        """Perform a quick port scan on common ports"""
        if self.nmap_available:
            common_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
            return self.scan_ports(target, ports=common_ports, arguments='-v -sV -O --version-light')
        else:
            # Use socket scanning for common ports
            common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
            return self.socket_scan_ports(target, common_ports)

    def udp_scan(self, target):
        """Perform UDP port scan"""
        if self.nmap_available:
            return self.scan_ports(target, ports='1-65535', arguments='-v -sU')
        else:
            # UDP scanning with sockets is complex, return message about limitation
            return {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'error': 'UDP scanning requires nmap. Install nmap or use TCP scanning.',
                'command_line': 'UDP scan not available without nmap'
            }

    def aggressive_scan(self, target):
        """Perform aggressive scan with service detection and OS fingerprinting"""
        if self.nmap_available:
            return self.scan_ports(target, ports='1-65535', arguments='-v -sS -A -T4')
        else:
            # Fall back to comprehensive TCP scan
            common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,9000,9090,9200,9300]
            return self.socket_scan_ports(target, common_ports)

def format_scan_results(results):
    """Format scan results for display"""
    if 'error' in results:
        return f"Error: {results['error']}"

    output = f"Port Scan Results for {results['target']}\n"
    output += f"Scan Time: {results['scan_time']}\n"
    output += f"Command: {results.get('command_line', 'N/A')}\n\n"

    for host in results.get('hosts', []):
        output += f"Host: {host['host']} ({host.get('hostname', 'Unknown')})\n"
        output += f"State: {host['state']}\n"

        if host.get('os_detection'):
            output += "OS Detection:\n"
            for os_match in host['os_detection'][:3]:  # Top 3 matches
                output += f"  {os_match.get('name', 'Unknown')} ({os_match.get('accuracy', '0')}%)\n"

        for protocol in host.get('protocols', []):
            output += f"\n{protocol['protocol'].upper()} Ports:\n"
            for port_info in protocol.get('ports', []):
                if port_info['state'] == 'open':
                    output += f"  {port_info['port']}/{protocol['protocol']} {port_info['state']} {port_info['service']}"
                    if port_info.get('version'):
                        output += f" {port_info['version']}"
                    if port_info.get('product'):
                        output += f" ({port_info['product']})"
                    output += "\n"

        output += "\n" + "="*50 + "\n"

    return output