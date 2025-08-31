import nmap
import json
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_ports(self, target, ports='1-65535', arguments='-v -sS -O'):
        """
        Perform comprehensive port scanning
        Args:
            target: IP address or hostname
            ports: Port range to scan (default: all ports)
            arguments: Nmap arguments
        Returns:
            dict: Scan results
        """
        try:
            print(f"Starting port scan on {target} with ports {ports}")

            # Perform the scan
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

        except Exception as e:
            return {
                'error': f'Port scan failed: {str(e)}',
                'target': target,
                'scan_time': datetime.now().isoformat()
            }

    def quick_scan(self, target):
        """Perform a quick port scan on common ports"""
        common_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
        return self.scan_ports(target, ports=common_ports, arguments='-v -sV -O --version-light')

    def udp_scan(self, target):
        """Perform UDP port scan"""
        return self.scan_ports(target, ports='1-65535', arguments='-v -sU')

    def aggressive_scan(self, target):
        """Perform aggressive scan with service detection and OS fingerprinting"""
        return self.scan_ports(target, ports='1-65535', arguments='-v -sS -A -T4')

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