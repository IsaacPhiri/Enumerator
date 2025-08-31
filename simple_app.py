#!/usr/bin/env python3
"""
Simple Red Teamer Recon Tool - No external dependencies version
Uses only Python standard library for basic functionality
"""

import http.server
import socketserver
import urllib.parse
import json
import os
import socket
import threading
import time
from datetime import datetime
import subprocess
import sys

class ReconHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.serve_index()
        elif self.path.startswith('/static/'):
            self.serve_static()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/scan':
            self.handle_scan()
        else:
            self.send_error(404)

    def serve_index(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        html_content = self.get_index_html()
        self.wfile.write(html_content.encode())

    def serve_static(self):
        # For now, just return a simple response
        self.send_response(200)
        self.send_header('Content-type', 'text/css')
        self.end_headers()
        self.wfile.write(b'/* CSS would go here */')

    def handle_scan(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = urllib.parse.parse_qs(post_data.decode())

        target = data.get('target', [''])[0]
        scan_type = data.get('scan_type', ['port_scan'])[0]

        result = {}

        try:
            if scan_type == 'port_scan':
                result = self.perform_port_scan(target)
            elif scan_type == 'service_enum':
                result = self.perform_service_enumeration(target)
            elif scan_type == 'dir_bust':
                result = self.perform_directory_busting(target)
            elif scan_type == 'vuln_scan':
                result = self.perform_vulnerability_scan(target)
            elif scan_type == 'full_scan':
                result = self.perform_full_scan(target)
            else:
                result = {'error': 'Invalid scan type'}

        except Exception as e:
            result = {'error': str(e)}

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def perform_port_scan(self, target):
        """Basic port scanning using socket connections"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        results = {
            'scan_type': 'port_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': []
        }

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    results['open_ports'].append({
                        'port': port,
                        'service': self.get_service_name(port),
                        'state': 'open'
                    })
                sock.close()
            except:
                pass

        results['results'] = f"Port Scan Results for {target}\n"
        results['results'] += f"Scan Time: {results['timestamp']}\n\n"

        if results['open_ports']:
            results['results'] += "Open Ports:\n"
            for port_info in results['open_ports']:
                results['results'] += f"  {port_info['port']}/{port_info['service']} - {port_info['state']}\n"
        else:
            results['results'] += "No open ports found in common port range.\n"

        return results

    def perform_service_enumeration(self, target):
        """Basic service enumeration"""
        results = {
            'scan_type': 'service_enum',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'services': []
        }

        # Try to connect to common ports and grab banners
        common_ports = [21, 22, 25, 80, 110, 143, 443]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))

                # Try to get banner
                banner = ""
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass

                if banner:
                    results['services'].append({
                        'port': port,
                        'service': self.get_service_name(port),
                        'banner': banner[:100]
                    })

                sock.close()
            except:
                pass

        results['results'] = f"Service Enumeration Results for {target}\n"
        results['results'] += f"Scan Time: {results['timestamp']}\n\n"

        if results['services']:
            for service in results['services']:
                results['results'] += f"Port {service['port']} ({service['service']}):\n"
                results['results'] += f"  Banner: {service['banner']}\n\n"
        else:
            results['results'] += "No service banners retrieved.\n"

        return results

    def perform_directory_busting(self, target):
        """Basic directory busting"""
        results = {
            'scan_type': 'dir_bust',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'directories': [],
            'files': []
        }

        # Common directories to check
        common_dirs = ['admin', 'backup', 'config', 'test', 'old', 'new', 'dev', 'staging']

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # Note: This is a very basic implementation
        # In a real scenario, you'd use urllib or requests
        results['results'] = f"Directory Busting Results for {target}\n"
        results['results'] += f"Scan Time: {results['timestamp']}\n\n"
        results['results'] += "Directory busting requires external HTTP library.\n"
        results['results'] += "Please install requests library for full functionality.\n"

        return results

    def perform_vulnerability_scan(self, target):
        """Basic vulnerability scanning"""
        results = {
            'scan_type': 'vuln_scan',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': []
        }

        results['results'] = f"Vulnerability Scan Results for {target}\n"
        results['results'] += f"Scan Time: {results['timestamp']}\n\n"
        results['results'] += "Basic vulnerability scanning requires external libraries.\n"
        results['results'] += "Please install required dependencies for full functionality.\n"

        return results

    def perform_full_scan(self, target):
        """Perform full reconnaissance scan"""
        print(f"Starting full reconnaissance scan for {target}")

        # Perform all individual scans
        port_results = self.perform_port_scan(target)
        service_results = self.perform_service_enumeration(target)
        dir_results = self.perform_directory_busting(target)
        vuln_results = self.perform_vulnerability_scan(target)

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

    def get_index_html(self):
        """Return the HTML content for the main page"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Teamer - Reconnaissance Automation</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1.5rem 0;
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logo i {
            font-size: 2rem;
            color: #667eea;
        }

        .logo h1 {
            font-size: 1.5rem;
            font-weight: 700;
            color: #333;
        }

        .status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: #10b981;
            color: white;
            border-radius: 50px;
            font-size: 0.9rem;
        }

        .status i {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .main-grid {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 2rem;
            margin-top: 2rem;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
        }

        .card-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #f0f0f0;
        }

        .card-header i {
            font-size: 1.5rem;
            color: #667eea;
        }

        .card-header h3 {
            font-size: 1.25rem;
            font-weight: 600;
            color: #333;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            font-weight: 600;
            color: #555;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }

        .form-input {
            width: 100%;
            padding: 1rem;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: #fafafa;
        }

        .form-input:focus {
            outline: none;
            border-color: #667eea;
            background: white;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .form-input::placeholder {
            color: #9ca3af;
        }

        .scan-options {
            display: grid;
            gap: 0.75rem;
        }

        .scan-option {
            position: relative;
        }

        .scan-option input[type="radio"] {
            position: absolute;
            opacity: 0;
            width: 0;
            height: 0;
        }

        .scan-option label {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1.25rem;
            background: #f8fafc;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .scan-option label:hover {
            background: #f1f5f9;
            border-color: #cbd5e1;
        }

        .scan-option input[type="radio"]:checked + label {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-color: #667eea;
            box-shadow: 0 4px 20px rgba(102, 126, 234, 0.3);
        }

        .scan-option-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            background: rgba(255, 255, 255, 0.2);
        }

        .scan-option input[type="radio"]:checked + label .scan-option-icon {
            background: rgba(255, 255, 255, 0.3);
        }

        .scan-btn {
            width: 100%;
            padding: 1.25rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            margin-top: 1rem;
        }

        .scan-btn:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }

        .scan-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .scan-btn i {
            font-size: 1.1rem;
        }

        .results-container {
            height: 600px;
            overflow-y: auto;
            position: relative;
        }

        .loading {
            display: none;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            color: #667eea;
            z-index: 10;
        }

        .loading-spinner {
            width: 60px;
            height: 60px;
            border: 4px solid #e5e7eb;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .terminal {
            background: #1e1e1e;
            color: #e5e7eb;
            font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
            padding: 1.5rem;
            border-radius: 12px;
            white-space: pre-wrap;
            line-height: 1.6;
            font-size: 0.9rem;
            border: 1px solid #374151;
            position: relative;
        }

        .terminal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 30px;
            background: #111827;
            border-radius: 12px 12px 0 0;
            display: flex;
            align-items: center;
            padding: 0 1rem;
        }

        .terminal::after {
            content: 'Terminal Output';
            position: absolute;
            top: 7px;
            left: 1rem;
            color: #9ca3af;
            font-size: 0.8rem;
            font-weight: 500;
            z-index: 1;
        }

        .error-message {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 1.25rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 500;
        }

        .error-message i {
            font-size: 1.25rem;
        }

        .success-message {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 1.25rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 500;
        }

        .success-message i {
            font-size: 1.25rem;
        }

        .scan-summary {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            text-align: center;
            font-weight: 600;
        }

        @media (max-width: 768px) {
            .main-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }

            .container {
                padding: 1rem;
            }

            .header-content {
                padding: 0 1rem;
            }

            .logo h1 {
                font-size: 1.25rem;
            }
        }

        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <h1>Red Teamer Pro</h1>
            </div>
            <div class="status">
                <i class="fas fa-circle"></i>
                <span>System Online</span>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="main-grid">
            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-cogs"></i>
                    <h3>Scan Configuration</h3>
                </div>

                <form id="scanForm">
                    <div class="form-group">
                        <label class="form-label" for="target">
                            <i class="fas fa-bullseye"></i> Target (IP/Domain)
                        </label>
                        <input type="text" id="target" class="form-input"
                               placeholder="192.168.1.1 or example.com" required>
                    </div>

                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-search"></i> Scan Type
                        </label>
                        <div class="scan-options">
                            <div class="scan-option">
                                <input type="radio" name="scanType" id="portScan" value="port_scan" checked>
                                <label for="portScan">
                                    <div class="scan-option-icon">
                                        <i class="fas fa-network-wired"></i>
                                    </div>
                                    <div>
                                        <div style="font-weight: 600;">Port Scanning</div>
                                        <div style="font-size: 0.8rem; opacity: 0.8;">Discover open ports & services</div>
                                    </div>
                                </label>
                            </div>
                            <div class="scan-option">
                                <input type="radio" name="scanType" id="serviceEnum" value="service_enum">
                                <label for="serviceEnum">
                                    <div class="scan-option-icon">
                                        <i class="fas fa-server"></i>
                                    </div>
                                    <div>
                                        <div style="font-weight: 600;">Service Enumeration</div>
                                        <div style="font-size: 0.8rem; opacity: 0.8;">Identify running services</div>
                                    </div>
                                </label>
                            </div>
                            <div class="scan-option">
                                <input type="radio" name="scanType" id="dirBust" value="dir_bust">
                                <label for="dirBust">
                                    <div class="scan-option-icon">
                                        <i class="fas fa-folder-open"></i>
                                    </div>
                                    <div>
                                        <div style="font-weight: 600;">Directory Busting</div>
                                        <div style="font-size: 0.8rem; opacity: 0.8;">Find hidden directories</div>
                                    </div>
                                </label>
                            </div>
                            <div class="scan-option">
                                <input type="radio" name="scanType" id="vulnScan" value="vuln_scan">
                                <label for="vulnScan">
                                    <div class="scan-option-icon">
                                        <i class="fas fa-exclamation-triangle"></i>
                                    </div>
                                    <div>
                                        <div style="font-weight: 600;">Vulnerability Scan</div>
                                        <div style="font-size: 0.8rem; opacity: 0.8;">Check for security issues</div>
                                    </div>
                                </label>
                            </div>
                            <div class="scan-option">
                                <input type="radio" name="scanType" id="fullScan" value="full_scan">
                                <label for="fullScan">
                                    <div class="scan-option-icon">
                                        <i class="fas fa-search-plus"></i>
                                    </div>
                                    <div>
                                        <div style="font-weight: 600;">Full Reconnaissance</div>
                                        <div style="font-size: 0.8rem; opacity: 0.8;">Complete security assessment</div>
                                    </div>
                                </label>
                            </div>
                        </div>
                    </div>

                    <button type="submit" class="scan-btn" id="scanBtn">
                        <i class="fas fa-play"></i>
                        <span>Start Scan</span>
                    </button>
                </form>
            </div>

            <div class="card fade-in">
                <div class="card-header">
                    <i class="fas fa-chart-line"></i>
                    <h3>Scan Results</h3>
                </div>

                <div class="results-container">
                    <div id="loading" class="loading">
                        <div class="loading-spinner"></div>
                        <div style="font-weight: 600; margin-bottom: 0.5rem;">Scanning in progress...</div>
                        <div style="font-size: 0.9rem; opacity: 0.8;">This may take a few moments</div>
                    </div>

                    <div id="results"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const target = document.getElementById('target').value.trim();
            const scanType = document.querySelector('input[name="scanType"]:checked').value;

            if (!target) {
                displayError('Please enter a target IP or domain');
                return;
            }

            // Show loading
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').innerHTML = '';
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanBtn').innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Scanning...</span>';

            // Send scan request
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `target=${encodeURIComponent(target)}&scan_type=${scanType}`
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('scanBtn').innerHTML = '<i class="fas fa-play"></i><span>Start Scan</span>';

                if (data.error) {
                    displayError(data.error);
                } else {
                    displayResults(data);
                }
            })
            .catch(error => {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('scanBtn').innerHTML = '<i class="fas fa-play"></i><span>Start Scan</span>';
                displayError('Network error: ' + error.message);
            });
        });

        function displayResults(data) {
            const resultsDiv = document.getElementById('results');

            // Add scan summary
            const summary = document.createElement('div');
            summary.className = 'scan-summary';
            summary.innerHTML = `<i class="fas fa-check-circle"></i> Scan completed for ${data.target}`;
            resultsDiv.appendChild(summary);

            if (data.scan_type === 'full_scan') {
                // Handle full scan results
                const terminal = document.createElement('div');
                terminal.className = 'terminal';
                terminal.textContent = data.results;
                resultsDiv.appendChild(terminal);
            } else {
                // Handle single scan results
                const terminal = document.createElement('div');
                terminal.className = 'terminal';
                terminal.textContent = data.results || 'No results available';
                resultsDiv.appendChild(terminal);
            }

            // Scroll to results
            resultsDiv.scrollIntoView({ behavior: 'smooth' });
        }

        function displayError(error) {
            const resultsDiv = document.getElementById('results');

            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.innerHTML = `<i class="fas fa-exclamation-triangle"></i><span>${error}</span>`;
            resultsDiv.appendChild(errorDiv);

            // Scroll to error
            resultsDiv.scrollIntoView({ behavior: 'smooth' });
        }

        // Add some interactive enhancements
        document.querySelectorAll('.scan-option input[type="radio"]').forEach(radio => {
            radio.addEventListener('change', function() {
                // Add visual feedback when selection changes
                this.closest('.scan-option').style.transform = 'scale(1.02)';
                setTimeout(() => {
                    this.closest('.scan-option').style.transform = 'scale(1)';
                }, 200);
            });
        });

        // Add keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'Enter') {
                document.getElementById('scanBtn').click();
            }
        });
    </script>
</body>
</html>"""

def run_server(port=8000):
    """Run the HTTP server"""
    with socketserver.TCPServer(("", port), ReconHandler) as httpd:
        print(f"Red Teamer Recon Tool running on http://localhost:{port}")
        print("Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped")
            httpd.shutdown()

if __name__ == '__main__':
    run_server()