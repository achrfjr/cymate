# CyMate Security Toolkit API

A comprehensive security toolkit API that provides a centralized platform for running various cybersecurity tools and analyses. This toolkit includes network scanning, web application security testing, malware detection, and threat intelligence capabilities.

## 🔧 Features

### Network Security Tools
- **DNS Hostname Scanning**: Analyze DNS records and detect subdomains
- **Firewall and ACL Testing**: Check if ports are blocked by firewalls
- **IP Scanning**: Scan IP ranges and detect live hosts
- **Port Scanning**: Scan ports and detect open services
- **Protocol Analysis**: Detect protocols and check for security risks
- **Service Detection**: Detect running services and their versions
- **Subnet and VLAN Scanning**: Scan subnets and detect VLAN misconfigurations
- **Latency Testing**: Measure network latency and packet loss

### Web Application Security Tools
- **SSRF Vulnerability Testing**: Test for Server-Side Request Forgery vulnerabilities
- **Web Config Scanner**: Scan for misconfigurations and default credentials
- **Cryptographic Demo**: Demonstrate insecure hashing and encryption practices
- **Design Checker**: Analyze design documents for insecure patterns
- **Vulnerability Scanner**: Scan Python requirements.txt for vulnerable packages
- **Software Integrity Checker**: Check for software integrity issues
- **Logging Failure Detection**: Detect logging configuration failures
- **Identification Failure Analysis**: Identify authentication and identification failures

### Malware Detection Tools
- **File Scanner**: Scan files for malicious patterns and calculate file hashes
- **URL Scanner**: Scan URLs for potentially malicious patterns

### Threat Intelligence
- **Threat Intelligence Scanner**: Collect and analyze threat intelligence from various sources

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- Python (v3.8 or higher)
- SQLite

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/fortestjr/grad-proj-final.git
   cd grad-proj-final
   ```

2. **Create and activate Python virtual environment**
   ```bash
   # Create virtual environment in the tools directory
   cd tools
   python -m venv cymatevenv
   
   # Activate virtual environment
   # On Windows:
   cymatevenv\Scripts\activate
   # On macOS/Linux:
   source cymatevenv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r ../requirements.txt
   ```

4. **Install Node.js dependencies**
   ```bash
   cd ..
   npm install
   ```

5. **Initialize the database**
   
   Run the automated setup script to populate the database with all security tools and categories:

   ```bash
   npm run setup
   ```
   
   This script will:
   - Create all necessary categories (Network, Web, Malware, Threat Intelligence)
   - Populate the database with 19 security tools
   - Show progress and provide a summary
   - Handle errors gracefully
   
   **Note:** This should only be run once during initial setup. The script uses `INSERT OR IGNORE` so it's safe to run multiple times without creating duplicates.

6. **Start the API server**
   ```bash
   npm start
   ```

   The API will be available at `http://localhost:3000`

## 🔗 API Endpoints

### Network Security
- `POST /network/dns` - DNS hostname scanning
- `POST /network/firewall` - Firewall and ACL testing
- `POST /network/ip` - IP scanning
- `POST /network/port` - Port scanning
- `POST /network/protocol` - Protocol analysis
- `POST /network/service` - Service detection
- `POST /network/subnet` - Subnet and VLAN scanning
- `POST /network/latency` - Latency testing

### Web Security
- `POST /web/ssrf` - SSRF vulnerability testing
- `POST /web/config` - Web configuration scanning
- `POST /web/crypto` - Cryptographic analysis
- `POST /web/design` - Design security analysis
- `POST /web/vuln` - Vulnerability scanning
- `POST /web/integrity` - Software integrity checking
- `POST /web/logging` - Logging failure detection
- `POST /web/identification` - Identification failure analysis

### Malware Detection
- `POST /malware/file` - File scanning (with file upload)
- `POST /malware/url` - URL scanning

### Threat Intelligence
- `POST /threat/analyze` - Threat intelligence analysis

## 🛠️ Usage Examples

### DNS Scanning
```bash
curl -X POST http://localhost:3000/network/dns \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### File Upload for Malware Scanning
```bash
curl -X POST http://localhost:3000/malware/file \
  -F "file=@suspicious_file.txt"
```

### SSRF Testing
```bash
curl -X POST http://localhost:3000/web/ssrf \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com"}'
```

## 📁 Project Structure

```
grad-prject/
├── controller/           # API route controllers
├── db/                  # Database files and connection logic
├── middleware/          # Express middleware
├── migrations/          # Database migration scripts
├── routes/             # API route definitions
├── services/           # Business logic services
├── setup/              # Setup and initialization scripts
├── tools/              # Python security tools
│   ├── cymatevenv/     # Python virtual environment
│   └── lib/            # Additional tool libraries
├── uploads/            # File upload storage
├── package.json        # Node.js dependencies
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## ⚠️ Security Considerations & Ethical Use

### 🔒 **IMPORTANT: Authorized Use Only**
This toolkit contains powerful security testing tools that can identify vulnerabilities and perform network reconnaissance. **You MUST have explicit written permission** before using these tools on any systems, networks, or applications that you do not own.

### 📋 **Legal Requirements**
- ✅ Obtain proper authorization before testing
- ✅ Comply with all applicable laws and regulations  
- ✅ Use only for legitimate security research and testing
- ✅ Report vulnerabilities through responsible disclosure
- ❌ **DO NOT** use for unauthorized access or malicious purposes

### 🛡️ **Technical Security**
- **Virtual Environment**: Always use the provided virtual environment to avoid conflicts
- **File Uploads**: Uploaded files are stored temporarily and should be managed appropriately  
- **API Security**: Consider implementing authentication and rate limiting for production use
- **Network Isolation**: Run in isolated environments when testing

### ⚖️ **Disclaimer**
The authors of this toolkit are not responsible for any misuse, damage, or legal consequences resulting from the use of these tools. Users assume full responsibility for ensuring their use complies with all applicable laws and ethical guidelines.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -am 'Add new security tool'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Create a Pull Request

## 📄 License

This project is licensed under the ISC License - see the LICENSE file for details.

## 🔍 Troubleshooting

### Common Issues

1. **Python Virtual Environment Issues**
   - Ensure you're in the `tools` directory when creating the virtual environment
   - Activate the virtual environment before installing dependencies
   - The API will automatically detect and use the virtual environment Python executable

2. **Database Migration Errors**
   - Run `npm run setup` to populate the database with security tools
   - Check that the SQLite database file has proper permissions
   - Ensure all migration scripts are run in order

3. **Port Already in Use**
   - Change the PORT environment variable or stop other processes using port 3000

4. **Python Tool Execution Errors**
   - Verify that all required Python packages are installed
   - Check that the virtual environment is activated when running tools
   - The service automatically detects the Python executable in `tools/cymatevenv`

5. **Missing Dependencies**
   - Run `python setup/scan_requirements.py` to scan for all required packages
   - This will generate an updated requirements.txt with all discovered dependencies

### Getting Help

If you encounter issues:
1. Check the logs in the console output
2. Verify all dependencies are properly installed
3. Ensure the database is properly initialized
4. Check that the Python virtual environment is activated

## 📞 Support

For support and questions, please open an issue in the GitHub repository.


