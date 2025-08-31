# 🔴 Red Teamer Pro - Reconnaissance Automation

A modern, professional web-based reconnaissance automation tool designed for CTF challenges and ethical hacking practice. Features a sleek, intuitive interface with powerful scanning capabilities, secure authentication, and comprehensive reporting.

## ✨ Features

### 🔍 **Core Scanning Capabilities**
- **Port Scanning**: Scan 20+ common ports to identify open services
- **Service Enumeration**: Gather service banners and version information
- **Directory Busting**: Discover hidden directories and files on web servers
- **Vulnerability Scanning**: Basic vulnerability detection and assessment
- **Full Reconnaissance**: Comprehensive scanning combining all techniques

### 🔐 **Security & Authentication**
- **Secure Login System**: Protected access with session management
- **User Authentication**: Username/password authentication
- **Session Management**: Automatic session handling and logout
- **Demo Accounts**: Pre-configured test credentials for easy access
- **Access Control**: Protected scanning functionality

### 🎨 **Modern User Interface**
- **Professional Landing Page**: Introduction with feature showcase
- **Sleek Design**: Gradient backgrounds and modern typography
- **Responsive Layout**: Works perfectly on desktop and mobile devices
- **Interactive Elements**: Smooth animations and hover effects
- **Real-time Feedback**: Live status updates and loading indicators
- **Intuitive Navigation**: Easy-to-use scan type selection with icons
- **Terminal-style Output**: Professional results display with syntax highlighting
- **User Dashboard**: Personalized interface with user information

## Installation

### Option 1: Standard Library Version (Recommended)

The `simple_app.py` uses only Python's standard library, making it easy to run without installing dependencies.

```bash
python simple_app.py
```

**Access**: `http://localhost:8080`

### Option 2: Full-Featured Version

For the full-featured version with advanced capabilities and Flask framework:

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

**Access**: `http://localhost:5000`

## 🔐 Authentication

Both versions include secure authentication:

### Demo Credentials
- **Username**: `admin`
- **Password**: `recon2024`

### Additional Test Account
- **Username**: `user`
- **Password**: `password123`

### User Flow
1. Visit the landing page
2. Click "Start Reconnaissance"
3. Login with demo credentials
4. Access the full dashboard
5. Logout when finished

## 🚀 Usage

### Quick Start

#### Standard Library Version
1. **Launch the application**:
   ```bash
   python simple_app.py
   ```

2. **Open your browser** and navigate to: `http://localhost:8080`

3. **Visit the landing page** and click "Start Reconnaissance"

4. **Login with demo credentials**:
   - Username: `admin`
   - Password: `recon2024`

5. **Access the dashboard** and start scanning

#### Full-Featured Version
1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Launch the application**:
   ```bash
   python app.py
   ```

3. **Open your browser** and navigate to: `http://localhost:5000`

4. **Follow the same authentication flow** as above

### 🔐 Authentication Flow
1. **Landing Page**: Professional introduction with feature overview
2. **Login Page**: Secure authentication with demo credentials
3. **Dashboard**: Full scanning interface with user information
4. **Logout**: Secure session termination

### 🎯 Scan Types

| Scan Type | Description | Use Case |
|-----------|-------------|----------|
| **Port Scanning** | Scans 20+ common ports | Initial reconnaissance |
| **Service Enumeration** | Identifies running services & versions | Service discovery |
| **Directory Busting** | Finds hidden web directories | Web application testing |
| **Vulnerability Scan** | Basic security assessment | Quick vulnerability check |
| **Full Reconnaissance** | Complete security assessment | Comprehensive analysis |

### 🎮 Interface Features

- **🏠 Landing Page**: Professional introduction with feature showcase
- **🔐 Secure Login**: Authentication system with demo credentials
- **👤 User Dashboard**: Personalized interface with user information
- **🎨 Modern Design**: Sleek gradients and professional typography
- **📱 Responsive**: Works on desktop, tablet, and mobile
- **⚡ Real-time**: Live status updates and loading indicators
- **⌨️ Shortcuts**: Ctrl+Enter to start scan quickly
- **🎯 Intuitive**: Visual scan type selection with icons
- **💻 Terminal Output**: Professional results display
- **🚪 Logout**: Secure session termination

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
├── simple_app.py          # Simple HTTP server (standard library only)
├── app.py                 # Full-featured Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   ├── index.html         # Main dashboard interface
│   ├── landing.html       # Professional landing page
│   └── login.html         # Authentication interface
├── modules/
│   ├── port_scanner.py    # Port scanning functionality
│   ├── service_enumerator.py  # Service enumeration
│   ├── dir_buster.py      # Directory busting
│   └── vuln_scanner.py    # Vulnerability scanning
├── static/                # Static assets (CSS, JS, images)
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## 🏗️ Architecture

### Two Implementation Options

#### 1. **Simple Version** (`simple_app.py`)
- **Dependencies**: Python standard library only
- **Server**: Built-in HTTP server
- **Authentication**: Cookie-based sessions
- **Port**: 8080
- **Best for**: Quick deployment, no external dependencies

#### 2. **Full-Featured Version** (`app.py`)
- **Framework**: Flask web framework
- **Authentication**: Flask-Session with filesystem storage
- **Database**: Ready for SQLite/PostgreSQL integration
- **Port**: 5000
- **Best for**: Production use, advanced features

### 🔐 Security Features

- **Session Management**: Secure session handling with expiration
- **Access Control**: Protected routes requiring authentication
- **Input Validation**: Sanitized user inputs
- **Error Handling**: Comprehensive error management
- **Logout Functionality**: Secure session termination

## Security Notice

This tool is intended for:
- Educational purposes
- CTF challenges
- Authorized security testing
- Ethical hacking practice

**Do not use this tool against systems without explicit permission.**

## Requirements

### System Requirements
- **Python**: 3.6 or higher
- **Operating System**: Windows, macOS, or Linux
- **Browser**: Modern web browser (Chrome, Firefox, Safari, Edge)

### Dependencies

#### Standard Library Version (`simple_app.py`)
- **No external dependencies required**
- Uses only Python's built-in modules
- Perfect for quick deployment and testing

#### Full-Featured Version (`app.py`)
- **Flask**: Web framework
- **Flask-Session**: Session management
- **python-nmap**: Advanced port scanning
- **requests**: HTTP library for directory busting
- **beautifulsoup4**: HTML parsing
- **scapy**: Network packet manipulation
- **paramiko**: SSH connections

### Installation Commands

```bash
# For standard library version (no dependencies needed)
python simple_app.py

# For full-featured version
pip install -r requirements.txt
python app.py
```

## 🚀 Deployment & Testing

### Quick Test
```bash
# Test the standard library version
python simple_app.py
# Visit: http://localhost:8080

# Test the full-featured version
pip install -r requirements.txt
python app.py
# Visit: http://localhost:5000
```

### Demo Credentials
- **Username**: `admin` | **Password**: `recon2024`
- **Username**: `user` | **Password**: `password123`

### Sample Targets for Testing
- `scanme.nmap.org` - Legal testing target
- `testphp.vulnweb.com` - Vulnerable web application
- Local network IPs (with permission)

## 🔧 Development

### Adding New Features
1. **Scanning Modules**: Add to `modules/` directory
2. **UI Components**: Update templates in `templates/`
3. **Authentication**: Modify user database in respective app files
4. **Routes**: Add new endpoints following existing patterns

### Code Quality
- **Modular Design**: Separate concerns across files
- **Error Handling**: Comprehensive exception management
- **Security**: Input validation and secure practices
- **Documentation**: Clear comments and docstrings

## 🤝 Contributing

Feel free to contribute improvements, bug fixes, or additional scanning modules.

### Ways to Contribute
- 🐛 **Bug Reports**: Open issues for problems found
- ✨ **Feature Requests**: Suggest new scanning capabilities
- 🔧 **Code Improvements**: Submit pull requests
- 📖 **Documentation**: Improve README and code comments

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

## 🎯 Latest Updates

### Version 2.0 Features
- ✅ **Landing Page**: Professional introduction interface
- ✅ **Authentication System**: Secure login with session management
- ✅ **User Dashboard**: Personalized scanning interface
- ✅ **Dual Implementation**: Standard library and Flask versions
- ✅ **Enhanced Security**: Protected routes and access control
- ✅ **Modern UI**: Updated design with animations and gradients
- ✅ **Demo Accounts**: Pre-configured test credentials

### Quick Access
- **Standard Library**: `python simple_app.py` → `http://localhost:8080`
- **Full-Featured**: `python app.py` → `http://localhost:5000`
- **Demo Login**: `admin` / `recon2024`