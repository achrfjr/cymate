# Setup Scripts

This directory contains setup scripts for initializing the CyMate Security Toolkit.

## Database Population

The `populate_database.js` script automatically sets up the database with all security tools and categories.

## Requirements Scanner

The `scan_requirements.py` script analyzes all Python tools to discover dependencies and generate an updated requirements.txt file.

### Usage

Run this script **only once** during initial setup:

```bash
# From the project root directory
node setup/populate_database.js
```

### What it does:

1. **Creates Categories:**
   - Network (Network security and scanning tools)
   - Web (Web application security tools)  
   - Malware (Malware detection tools)
   - Threat Intelligence (Threat analysis tools)

2. **Populates Security Tools:**
   - 8 Web Security Tools (SSRF, Config Scanner, Crypto Demo, etc.)
   - 8 Network Security Tools (DNS, Firewall Testing, Port Scanning, etc.)
   - 2 Malware Detection Tools (File Scanner, URL Scanner)
   - 1 Threat Intelligence Tool

3. **Provides Feedback:**
   - Shows progress for each tool added
   - Displays summary of total categories and tools
   - Handles errors gracefully

### Requirements

- Node.js environment
- Database connection established
- Proper file structure in place

### Notes

- Uses `INSERT OR IGNORE` to prevent duplicate entries
- Safe to run multiple times (won't create duplicates)
- Automatically exits with appropriate status codes

## Requirements Scanning

### Usage

To scan all Python tools and update requirements.txt:

```bash
# From the project root directory
python setup/scan_requirements.py
```

### What it does:

1. **Scans Python Files:**
   - Analyzes all .py files in the tools directory
   - Uses AST parsing to extract import statements accurately
   - Falls back to regex parsing if AST fails

2. **Categorizes Dependencies:**
   - Separates standard library modules from third-party packages
   - Identifies known package name mappings (e.g., `nmap` → `python-nmap`)
   - Provides version constraints for known packages

3. **Generates Requirements:**
   - Creates a properly formatted requirements.txt
   - Groups dependencies by category
   - Includes comments explaining built-in modules
   - Offers to write the file automatically

### Requirements

- Python 3.6+ (uses AST and pathlib)
- Read access to tools directory

### Notes

- Automatically handles package name mappings
- Safe to run multiple times
- Interactive prompts before overwriting files 