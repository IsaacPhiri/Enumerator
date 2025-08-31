from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import os
import subprocess
import json
from datetime import datetime
from functools import wraps
from modules.port_scanner import PortScanner, format_scan_results
from modules.service_enumerator import ServiceEnumerator, format_service_results
from modules.dir_buster import DirectoryBuster, format_dirbust_results
from modules.vuln_scanner import VulnerabilityScanner, format_vuln_results

app = Flask(__name__)
app.secret_key = 'red-teamer-pro-secret-key-2024'
app.config['SESSION_TYPE'] = 'filesystem'

# Ensure directories exist
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('modules', exist_ok=True)

# Simple user database (in production, use proper database)
USERS = {
    'admin': 'recon2024',
    'user': 'password123'
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in USERS and USERS[username] == password:
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user', None)
    return redirect(url_for('landing'))

@app.route('/scan', methods=['POST'])
@login_required
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

        # Check if scan was successful
        if 'error' in scan_results:
            return {
                'scan_type': 'port_scan',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': f'Port scan failed: {scan_results["error"]}',
                'errors': scan_results['error'],
                'hosts': []
            }

        formatted_results = format_scan_results(scan_results)

        return {
            'scan_type': 'port_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': '',
            'hosts': scan_results.get('hosts', [])
        }
    except Exception as e:
        return {
            'scan_type': 'port_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Port scan failed: {str(e)}',
            'errors': str(e),
            'hosts': []
        }

def perform_service_enumeration(target):
    """Perform comprehensive service enumeration"""
    try:
        enumerator = ServiceEnumerator()
        enum_results = enumerator.enumerate_services(target)

        # Check if enumeration was successful
        if 'error' in enum_results:
            return {
                'scan_type': 'service_enum',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': f'Service enumeration failed: {enum_results["error"]}',
                'errors': enum_results['error'],
                'services': []
            }

        formatted_results = format_service_results(enum_results)

        return {
            'scan_type': 'service_enum',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': '',
            'services': enum_results.get('services', [])
        }
    except Exception as e:
        return {
            'scan_type': 'service_enum',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Service enumeration failed: {str(e)}',
            'errors': str(e),
            'services': []
        }

def perform_directory_busting(target):
    """Perform directory busting on web server"""
    try:
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        buster = DirectoryBuster()
        bust_results = buster.bust_directories(target)

        # Check if directory busting was successful
        if 'error' in bust_results:
            return {
                'scan_type': 'dir_bust',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': f'Directory busting failed: {bust_results["error"]}',
                'errors': bust_results['error'],
                'directories': [],
                'files': []
            }

        formatted_results = format_dirbust_results(bust_results)

        return {
            'scan_type': 'dir_bust',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': '; '.join(bust_results.get('errors', [])),
            'directories': bust_results.get('directories', []),
            'files': bust_results.get('files', [])
        }
    except Exception as e:
        return {
            'scan_type': 'dir_bust',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Directory busting failed: {str(e)}',
            'errors': str(e),
            'directories': [],
            'files': []
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

        # Check if vulnerability scan was successful
        if 'error' in vuln_results:
            return {
                'scan_type': 'vuln_scan',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': f'Vulnerability scanning failed: {vuln_results["error"]}',
                'errors': vuln_results['error'],
                'vulnerabilities': []
            }

        formatted_results = format_vuln_results(vuln_results)

        return {
            'scan_type': 'vuln_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': formatted_results,
            'errors': '',
            'vulnerabilities': vuln_results.get('vulnerabilities', [])
        }
    except Exception as e:
        return {
            'scan_type': 'vuln_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': f'Vulnerability scanning failed: {str(e)}',
            'errors': str(e),
            'vulnerabilities': []
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

    # Extract open ports from the port scanner results
    open_ports = []
    if 'hosts' in port_results:
        for host in port_results['hosts']:
            for protocol in host.get('protocols', []):
                for port_info in protocol.get('ports', []):
                    if port_info.get('state') == 'open':
                        open_ports.append(port_info)

    if open_ports:
        output += f"Found {len(open_ports)} open ports:\n\n"
        for port_info in open_ports:
            output += f"  📡 Port {port_info['port']}/{port_info['service']} - {port_info['state'].upper()}\n"
            if port_info.get('version'):
                output += f"     Version: {port_info['version']}\n"
            if port_info.get('product'):
                output += f"     Product: {port_info['product']}\n"
    else:
        output += "No open ports found in common port range.\n"
    output += "\n"

    # Service Enumeration Results
    output += "🖥️ SERVICE ENUMERATION RESULTS\n"
    output += "-" * 30 + "\n"
    if service_results.get('services'):
        # Filter out services with errors and count successful enumerations
        successful_services = [s for s in service_results['services'] if 'error' not in s and s.get('state') == 'open']
        output += f"Retrieved {len(successful_services)} service banners:\n\n"
        for service in successful_services:
            output += f"  🔧 Port {service['port']} ({service['service']}):\n"
            if service.get('banner'):
                banner = service['banner'][:100] + ('...' if len(service['banner']) > 100 else '')
                output += f"     Banner: {banner}\n"
            if service.get('version'):
                output += f"     Version: {service['version']}\n"
            if service.get('server'):
                output += f"     Server: {service['server']}\n"
            if service.get('technologies'):
                output += f"     Technologies: {', '.join(service['technologies'])}\n"
    else:
        output += "No service banners retrieved.\n"
    output += "\n"

    # Directory Busting Results
    output += "📁 DIRECTORY BUSTING RESULTS\n"
    output += "-" * 30 + "\n"
    directories_found = len(dir_results.get('directories', []))
    files_found = len(dir_results.get('files', []))
    if directories_found > 0 or files_found > 0:
        output += f"Found {directories_found} directories and {files_found} files:\n\n"
        for directory in dir_results.get('directories', [])[:5]:  # Show first 5
            output += f"  📁 {directory.get('path', 'Unknown')}\n"
        for file in dir_results.get('files', [])[:5]:  # Show first 5
            output += f"  📄 {file.get('path', 'Unknown')}\n"
        if directories_found > 5 or files_found > 5:
            output += f"  ... and {directories_found + files_found - 10} more items\n"
    else:
        output += dir_results.get('results', 'Directory busting requires external HTTP library.\n')
    output += "\n"

    # Vulnerability Scan Results
    output += "⚠️ VULNERABILITY SCAN RESULTS\n"
    output += "-" * 30 + "\n"
    vulnerabilities_found = len(vuln_results.get('vulnerabilities', []))
    if vulnerabilities_found > 0:
        output += f"Found {vulnerabilities_found} potential vulnerabilities:\n\n"
        for vuln in vuln_results.get('vulnerabilities', [])[:5]:  # Show first 5
            severity = vuln.get('severity', 'unknown').upper()
            output += f"  {severity}: {vuln.get('title', 'Unknown vulnerability')}\n"
        if vulnerabilities_found > 5:
            output += f"  ... and {vulnerabilities_found - 5} more vulnerabilities\n"
    else:
        output += vuln_results.get('results', 'Vulnerability scanning requires external libraries.\n')
    output += "\n"

    # Summary
    output += "📊 SCAN SUMMARY\n"
    output += "-" * 30 + "\n"

    # Check if port scan found any open ports
    port_success = len(open_ports) > 0
    output += f"• Port Scan: {'✅ Completed' if port_success else '❌ No open ports found'}\n"

    # Check if service enumeration found any services
    service_success = len([s for s in service_results.get('services', []) if 'error' not in s and s.get('state') == 'open']) > 0
    output += f"• Service Enum: {'✅ Completed' if service_success else '❌ No services found'}\n"

    # Check directory busting results
    dir_success = len(dir_results.get('directories', [])) > 0 or len(dir_results.get('files', [])) > 0
    output += f"• Directory Busting: {'✅ Completed' if dir_success else '⚠️ Limited functionality'}\n"

    # Check vulnerability scan results
    vuln_success = len(vuln_results.get('vulnerabilities', [])) > 0
    output += f"• Vulnerability Scan: {'✅ Completed' if vuln_success else '⚠️ Limited functionality'}\n"
    output += "\n"

    output += "🎯 RECOMMENDATIONS\n"
    output += "-" * 30 + "\n"
    if port_success:
        output += "• Consider securing open ports with firewalls\n"
        output += "• Review service configurations for vulnerabilities\n"
    if not service_success:
        output += "• All scanned services appear to be filtered or down\n"
    output += "• For advanced scanning, install required dependencies\n"

    output += "\n" + "=" * 60 + "\n"
    output += "🔴 FULL RECONNAISSANCE SCAN COMPLETED\n"
    output += "=" * 60 + "\n"

    results['results'] = output
    return results

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)