# 🔴 Red Teamer Pro - Reconnaissance Automation

A modern, professional web-based reconnaissance automation tool designed for CTF challenges and ethical hacking practice. Features a sleek, intuitive interface with powerful scanning capabilities.

## ✨ Features

### 🔍 **Core Scanning Capabilities**
- **Port Scanning**: Scan 20+ common ports to identify open services
- **Service Enumeration**: Gather service banners and version information
- **Directory Busting**: Discover hidden directories and files on web servers
- **Vulnerability Scanning**: Basic vulnerability detection and assessment
- **Full Reconnaissance**: Comprehensive scanning combining all techniques

### 🎨 **Modern User Interface**
- **Sleek Design**: Professional gradient backgrounds and modern typography
- **Responsive Layout**: Works perfectly on desktop and mobile devices
- **Interactive Elements**: Smooth animations and hover effects
- **Real-time Feedback**: Live status updates and loading indicators
- **Intuitive Navigation**: Easy-to-use scan type selection with icons
- **Terminal-style Output**: Professional results display with syntax highlighting

## Installation

### Option 1: Standard Library Version (Recommended)

The `simple_app.py` uses only Python's standard library, making it easy to run without installing dependencies.

```bash
python simple_app.py
```

### Option 2: Full-Featured Version

For the full-featured version with advanced capabilities:

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

## 🚀 Usage

### Quick Start
1. **Launch the application**:
   ```bash
   python simple_app.py
   ```

2. **Open your browser** and navigate to: `http://localhost:8000`

3. **Enter target details** and select scan type

4. **Click "Start Scan"** and view results in real-time

### 🎯 Scan Types

| Scan Type | Description | Use Case |
|-----------|-------------|----------|
| **Port Scanning** | Scans 20+ common ports | Initial reconnaissance |
| **Service Enumeration** | Identifies running services & versions | Service discovery |
| **Directory Busting** | Finds hidden web directories | Web application testing |
| **Vulnerability Scan** | Basic security assessment | Quick vulnerability check |
| **Full Reconnaissance** | Complete security assessment | Comprehensive analysis |

### 🎮 Interface Features

- **🎨 Modern Design**: Sleek gradients and professional typography
- **📱 Responsive**: Works on desktop, tablet, and mobile
- **⚡ Real-time**: Live status updates and loading indicators
- **⌨️ Shortcuts**: Ctrl+Enter to start scan quickly
- **🎯 Intuitive**: Visual scan type selection with icons
- **💻 Terminal Output**: Professional results display

## Scan Types Explained

### Port Scanning
- Scans 20+ common ports (21, 22, 23, 25, 53, 80, etc.)
- Identifies open ports and associated services
- Uses socket connections for reliability

### Service Enumeration
- Attempts to connect to open ports
- Grabs service banners and version information
- Identifies running services (FTP, SSH, HTTP, etc.)

### Directory Busting
- Tests common directory names on web servers
- Identifies potentially exposed directories
- Helps discover hidden web content

### Vulnerability Scanning
- Checks for common web vulnerabilities
- Identifies missing security headers
- Detects potentially vulnerable configurations

### Full Reconnaissance
- Combines all scanning techniques
- Provides comprehensive target assessment
- Generates detailed reports

## Project Structure

```
Enumerator/
├── simple_app.py          # Main application (standard library only)
├── app.py                 # Full-featured Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html        # Web interface
├── modules/
│   ├── port_scanner.py   # Port scanning functionality
│   ├── service_enumerator.py  # Service enumeration
│   ├── dir_buster.py     # Directory busting
│   └── vuln_scanner.py   # Vulnerability scanning
└── README.md             # This file
```

## Security Notice

This tool is intended for:
- Educational purposes
- CTF challenges
- Authorized security testing
- Ethical hacking practice

**Do not use this tool against systems without explicit permission.**

## Requirements

- Python 3.6+
- For full version: Flask, python-nmap, requests, and other dependencies listed in `requirements.txt`

## Contributing

Feel free to contribute improvements, bug fixes, or additional scanning modules.

## License

This project is for educational purposes. Use responsibly and ethically.