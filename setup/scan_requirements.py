#!/usr/bin/env python3
"""
Script to scan all Python files in the tools directory and extract import statements.
This helps create a comprehensive requirements.txt file.
"""

import os
import re
import ast
import sys
from pathlib import Path
from typing import Set, List

def extract_imports_from_file(file_path: Path) -> Set[str]:
    """Extract import statements from a Python file."""
    imports = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Parse the AST to get imports
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.add(name.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except SyntaxError:
            # If AST parsing fails, fall back to regex
            import_patterns = [
                r'^import\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                r'^from\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+import'
            ]
            
            for line in content.split('\n'):
                line = line.strip()
                for pattern in import_patterns:
                    match = re.match(pattern, line)
                    if match:
                        imports.add(match.group(1))
    
    except Exception as e:
        print(f"Warning: Could not process {file_path}: {e}")
    
    return imports

def get_standard_library_modules() -> Set[str]:
    """Return a set of Python standard library modules."""
    # Common standard library modules that don't need to be installed
    return {
        'os', 'sys', 'json', 'time', 'datetime', 'logging', 'argparse',
        'socket', 'ssl', 'hashlib', 'base64', 're', 'typing', 'uuid',
        'pathlib', 'statistics', 'math', 'collections', 'warnings',
        'stat', 'urllib', 'abc', 'io', 'subprocess', 'threading',
        'multiprocessing', 'functools', 'itertools', 'operator',
        'tempfile', 'shutil', 'glob', 'fnmatch', 'random', 'string',
        'decimal', 'fractions', 'copy', 'pickle', 'sqlite3', 'csv',
        'configparser', 'email', 'html', 'http', 'xml', 'zipfile',
        'tarfile', 'gzip', 'bz2', 'lzma', 'platform', 'gc'
    }

def scan_tools_directory() -> dict:
    """Scan all Python files in the tools directory."""
    tools_dir = Path(__file__).parent.parent / 'tools'
    all_imports = set()
    file_imports = {}
    
    if not tools_dir.exists():
        print(f"Tools directory not found: {tools_dir}")
        return {}
    
    # Find all Python files
    python_files = list(tools_dir.rglob('*.py'))
    
    print(f"Scanning {len(python_files)} Python files...")
    
    for file_path in python_files:
        print(f"  Processing: {file_path.relative_to(tools_dir)}")
        imports = extract_imports_from_file(file_path)
        file_imports[str(file_path.relative_to(tools_dir))] = imports
        all_imports.update(imports)
    
    return {
        'all_imports': all_imports,
        'file_imports': file_imports,
        'total_files': len(python_files)
    }

def categorize_imports(all_imports: Set[str]) -> dict:
    """Categorize imports into standard library and third-party packages."""
    standard_lib = get_standard_library_modules()
    
    third_party = set()
    standard = set()
    
    for imp in all_imports:
        if imp in standard_lib:
            standard.add(imp)
        else:
            third_party.add(imp)
    
    return {
        'third_party': sorted(third_party),
        'standard_library': sorted(standard)
    }

def generate_requirements_content(third_party: List[str]) -> str:
    """Generate content for requirements.txt file."""
    
    # Known version mappings for common packages
    version_mappings = {
        'requests': '>=2.25.1',
        'urllib3': '>=1.26.0',
        'scapy': '>=2.4.0',
        'python-nmap': '>=0.6.1',
        'ping3': '>=2.6.0',
        'dnspython': '>=2.1.0',
        'cryptography': '>=3.4.0',
        'bcrypt': '>=3.2.0',
        'argon2-cffi': '>=21.0.0',
        'packaging': '>=20.0',
        'pyyaml': '>=5.4.0',
        'colorama': '>=0.4.0',
        'prometheus-client': '>=0.10.0',
        'statsd': '>=3.3.0',
        'nmap': 'python-nmap>=0.6.1',  # nmap package is actually python-nmap
        'yaml': 'pyyaml>=5.4.0',       # yaml package is actually pyyaml
        'dns': 'dnspython>=2.1.0'       # dns package is actually dnspython
    }
    
    content = []
    content.append("# Core HTTP and Network Libraries")
    content.append("requests>=2.25.1")
    content.append("urllib3>=1.26.0")
    content.append("")
    
    content.append("# Network Security Tools")
    content.append("scapy>=2.4.0")
    content.append("python-nmap>=0.6.1")
    content.append("ping3>=2.6.0")
    content.append("dnspython>=2.1.0")
    content.append("")
    
    content.append("# Cryptography and Security")
    content.append("cryptography>=3.4.0")
    content.append("bcrypt>=3.2.0")
    content.append("argon2-cffi>=21.0.0")
    content.append("")
    
    content.append("# Data Processing and Parsing")
    content.append("packaging>=20.0")
    content.append("pyyaml>=5.4.0")
    content.append("")
    
    content.append("# Command Line Interface")
    content.append("colorama>=0.4.0")
    content.append("")
    
    content.append("# Monitoring and Metrics")
    content.append("prometheus-client>=0.10.0")
    content.append("statsd>=3.3.0")
    content.append("")
    
    # Add any additional third-party packages found
    additional = []
    known_packages = {
        'requests', 'urllib3', 'scapy', 'ping3', 'cryptography', 
        'bcrypt', 'packaging', 'colorama', 'nmap', 'yaml', 'dns'
    }
    
    for pkg in third_party:
        if pkg not in known_packages and pkg not in ['argparse']:  # argparse is built-in
            if pkg in version_mappings:
                additional.append(version_mappings[pkg])
            else:
                additional.append(pkg)
    
    if additional:
        content.append("# Additional discovered dependencies")
        content.extend(sorted(additional))
        content.append("")
    
    content.append("# Note: The following are built-in Python modules and don't need to be installed:")
    content.append("# argparse, os, sys, json, time, datetime, logging, socket, ssl, hashlib,")
    content.append("# base64, re, typing, uuid, pathlib, statistics, math, collections, warnings, stat")
    
    return '\n'.join(content)

def main():
    """Main function."""
    print("🔍 Scanning Python tools for import statements...")
    
    # Scan all files
    scan_results = scan_tools_directory()
    
    if not scan_results:
        print("❌ No Python files found or scan failed.")
        sys.exit(1)
    
    # Categorize imports
    categories = categorize_imports(scan_results['all_imports'])
    
    # Print results
    print(f"\n📊 Scan Results:")
    print(f"  Total files scanned: {scan_results['total_files']}")
    print(f"  Total imports found: {len(scan_results['all_imports'])}")
    print(f"  Third-party packages: {len(categories['third_party'])}")
    print(f"  Standard library modules: {len(categories['standard_library'])}")
    
    print(f"\n📦 Third-party packages found:")
    for pkg in categories['third_party']:
        print(f"  - {pkg}")
    
    print(f"\n📚 Standard library modules found:")
    for pkg in categories['standard_library']:
        print(f"  - {pkg}")
    
    # Generate requirements.txt content
    requirements_content = generate_requirements_content(categories['third_party'])
    
    print(f"\n📄 Generated requirements.txt content:")
    print("=" * 50)
    print(requirements_content)
    print("=" * 50)
    
    # Offer to write to file
    response = input("\n💾 Write this content to requirements.txt? (y/N): ").strip().lower()
    if response in ['y', 'yes']:
        requirements_path = Path(__file__).parent.parent / 'requirements.txt'
        with open(requirements_path, 'w', encoding='utf-8') as f:
            f.write(requirements_content)
        print(f"✅ Requirements written to {requirements_path}")
    else:
        print("📋 Content not written. You can copy the content above manually.")

if __name__ == "__main__":
    main() 