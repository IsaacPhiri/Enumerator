from flask import Flask, render_template, request, jsonify
import os
import subprocess
import json
from datetime import datetime
from modules.port_scanner import PortScanner, format_scan_results
from modules.service_enumerator import ServiceEnumerator, format_service_results
from modules.dir_buster import DirectoryBuster, format_dirbust_results
from modules.vuln_scanner import VulnerabilityScanner, format_vuln_results

app = Flask(__name__)

# Ensure directories exist
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('modules', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    results = {}

    try:
        if scan_type == 'port_scan':
            results = perform_port_scan(target)
        elif scan_type == 'service_enum':
            results = perform_service_enumeration(target)
        elif scan_type == 'dir_bust':
            results = perform_directory_busting(target)
        elif scan_type == 'vuln_scan':
            results = perform_vulnerability_scan(target)
        elif scan_type == 'full_scan':
            results = perform_full_scan(target)
        else:
            return jsonify({'error': 'Invalid scan type'}), 400

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def perform_port_scan(target):
    """Perform comprehensive port scanning using nmap"""
    try:
        scanner = PortScanner()
        # Perform quick scan first for faster results
        scan_results = scanner.quick_scan(target)
        formatted_results = format_scan_results(scan_results)

        return {
            'scan_type': 'port_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': scan_results.get('error', '')
        }
    except Exception as e:
        return {
            'scan_type': 'port_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Port scan failed: {str(e)}',
            'errors': str(e)
        }

def perform_service_enumeration(target):
    """Perform comprehensive service enumeration"""
    try:
        enumerator = ServiceEnumerator()
        enum_results = enumerator.enumerate_services(target)
        formatted_results = format_service_results(enum_results)

        return {
            'scan_type': 'service_enum',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': ''
        }
    except Exception as e:
        return {
            'scan_type': 'service_enum',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Service enumeration failed: {str(e)}',
            'errors': str(e)
        }

def perform_directory_busting(target):
    """Perform directory busting on web server"""
    try:
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        buster = DirectoryBuster()
        bust_results = buster.bust_directories(target)
        formatted_results = format_dirbust_results(bust_results)

        return {
            'scan_type': 'dir_bust',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': '; '.join(bust_results.get('errors', []))
        }
    except Exception as e:
        return {
            'scan_type': 'dir_bust',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Directory busting failed: {str(e)}',
            'errors': str(e)
        }

def perform_vulnerability_scan(target):
    """Perform vulnerability scanning"""
    try:
        scanner = VulnerabilityScanner()

        # Determine scan type based on target
        if target.startswith(('http://', 'https://')) or '.' in target:
            scan_type = 'web'
        else:
            scan_type = 'network'

        vuln_results = scanner.scan_vulnerabilities(target, scan_type)
        formatted_results = format_vuln_results(vuln_results)

        return {
            'scan_type': 'vuln_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': vuln_results.get('error', '')
        }
    except Exception as e:
        return {
            'scan_type': 'vuln_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Vulnerability scanning failed: {str(e)}',
            'errors': str(e)
        }

def perform_full_scan(target):
    """Perform full reconnaissance scan"""
    print(f"Starting full reconnaissance scan for {target}")

    # Perform all individual scans
    port_results = perform_port_scan(target)
    service_results = perform_service_enumeration(target)
    dir_results = perform_directory_busting(target)
    vuln_results = perform_vulnerability_scan(target)

    results = {
        'scan_type': 'full_scan',
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'port_scan': port_results,
        'service_enum': service_results,
        'dir_bust': dir_results,
        'vuln_scan': vuln_results
    }

    # Combine all results into a comprehensive output
    output = f"🔴 FULL RECONNAISSANCE REPORT for {target}\n"
    output += "=" * 60 + "\n"
    output += f"Scan Started: {results['timestamp']}\n"
    output += f"Target: {target}\n\n"

    # Port Scan Results
    output += "🔍 PORT SCAN RESULTS\n"
    output += "-" * 30 + "\n"
    if port_results.get('open_ports'):
        output += f"Found {len(port_results['open_ports'])} open ports:\n\n"
        for port_info in port_results['open_ports']:
            output += f"  📡 Port {port_info['port']}/{port_info['service']} - {port_info['state'].upper()}\n"
    else:
        output += "No open ports found in common port range.\n"
    output += "\n"

    # Service Enumeration Results
    output += "🖥️ SERVICE ENUMERATION RESULTS\n"
    output += "-" * 30 + "\n"
    if service_results.get('services'):
        output += f"Retrieved {len(service_results['services'])} service banners:\n\n"
        for service in service_results['services']:
            output += f"  🔧 Port {service['port']} ({service['service']}):\n"
            output += f"     Banner: {service['banner']}\n"
    else:
        output += "No service banners retrieved.\n"
    output += "\n"

    # Directory Busting Results
    output += "📁 DIRECTORY BUSTING RESULTS\n"
    output += "-" * 30 + "\n"
    output += dir_results.get('results', 'Directory busting requires external HTTP library.\n')
    output += "\n"

    # Vulnerability Scan Results
    output += "⚠️ VULNERABILITY SCAN RESULTS\n"
    output += "-" * 30 + "\n"
    output += vuln_results.get('results', 'Vulnerability scanning requires external libraries.\n')
    output += "\n"

    # Summary
    output += "📊 SCAN SUMMARY\n"
    output += "-" * 30 + "\n"
    output += f"• Port Scan: {'✅ Completed' if port_results.get('open_ports') else '❌ No open ports found'}\n"
    output += f"• Service Enum: {'✅ Completed' if service_results.get('services') else '❌ No services found'}\n"
    output += f"• Directory Busting: {'✅ Completed' if 'Directory busting requires' not in dir_results.get('results', '') else '⚠️ Limited functionality'}\n"
    output += f"• Vulnerability Scan: {'✅ Completed' if 'Vulnerability scanning requires' not in vuln_results.get('results', '') else '⚠️ Limited functionality'}\n"
    output += "\n"

    output += "🎯 RECOMMENDATIONS\n"
    output += "-" * 30 + "\n"
    if port_results.get('open_ports'):
        output += "• Consider securing open ports with firewalls\n"
        output += "• Review service configurations for vulnerabilities\n"
    if not service_results.get('services'):
        output += "• All scanned services appear to be filtered or down\n"
    output += "• For advanced scanning, install required dependencies\n"

    output += "\n" + "=" * 60 + "\n"
    output += "🔴 FULL RECONNAISSANCE SCAN COMPLETED\n"
    output += "=" * 60 + "\n"

    results['results'] = output
    return results

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)