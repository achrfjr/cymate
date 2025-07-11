import re
import json
from datetime import datetime
import sys

class ThreatIntelligenceTool:
    def __init__(self):
        self.api_keys = {
            'virustotal': 'YOUR_VIRUSTOTAL_API_KEY',
            'abuseipdb': 'YOUR_ABUSEIPDB_API_KEY',
            'otx': 'YOUR_OTX_API_KEY'
        }
        self.malware_db = self._load_malware_database()
        
    def _load_malware_database(self):
        """Comprehensive malware database with historical and modern threats"""
        return {
            "iloveyou": {
                "name": "ILOVEYOU",
                "type": "Computer Worm",
                "description": "One of the most destructive viruses ever, spread via email with 'ILOVEYOU' subject in 2000.",
                "aliases": ["Love Bug", "Love Letter"],
                "first_seen": "2000-05-05",
                "targets": ["Windows systems"],
                "impact": "Estimated $10 billion in damages worldwide",
                "mitre_att&ck": ["T1204", "T1566", "T1486"],
                "references": [
                    "https://www.csoonline.com/article/567885/iloveyou-the-worm-that-brought-the-world-to-its-knees.html",
                    "https://en.wikipedia.org/wiki/ILOVEYOU"
                ]
            },
            "mydoom": {
                "name": "MyDoom",
                "type": "Worm",
                "description": "Fastest-spreading email worm in 2004, created backdoors in infected systems.",
                "aliases": ["Novarg", "Shimgapi"],
                "first_seen": "2004-01-26",
                "targets": ["Windows systems"],
                "impact": "Caused an estimated $38 billion in damages",
                "mitre_att&ck": ["T1204", "T1566", "T1133"],
                "references": [
                    "https://www.malwarebytes.com/mydoom",
                    "https://en.wikipedia.org/wiki/MyDoom"
                ]
            },
            "emotet": {
                "name": "Emotet",
                "type": "Banking Trojan",
                "description": "Advanced modular malware that evolved from banking trojan to malware delivery service.",
                "aliases": ["Heodo", "Geodo"],
                "first_seen": "2014",
                "targets": ["Financial institutions", "Government agencies"],
                "impact": "Responsible for 30% of malware attacks in 2019",
                "mitre_att&ck": ["T1071", "T1059", "T1204"],
                "references": [
                    "https://www.cisa.gov/emotet-malware",
                    "https://attack.mitre.org/software/S0367/"
                ]
            },
            "wannacry": {
                "name": "WannaCry",
                "type": "Ransomware",
                "description": "Global ransomware attack in 2017 exploiting Windows SMB vulnerability MS17-010.",
                "aliases": ["WannaCrypt", "WCry"],
                "first_seen": "2017-05-12",
                "targets": ["Global Windows systems"],
                "impact": "Affected 200,000+ computers across 150 countries",
                "mitre_att&ck": ["T1486", "T1210", "T1043"],
                "references": [
                    "https://www.cisa.gov/wannacry",
                    "https://attack.mitre.org/software/S0366/"
                ]
            },
            "notpetya": {
                "name": "NotPetya",
                "type": "Ransomware/Wiper",
                "description": "Destructive malware masquerading as ransomware, caused global outages in 2017.",
                "aliases": ["ExPetr", "GoldenEye"],
                "first_seen": "2017-06-27",
                "targets": ["Ukrainian businesses", "Global companies"],
                "impact": "Caused $10 billion in damages",
                "mitre_att&ck": ["T1486", "T1210", "T1490"],
                "references": [
                    "https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/",
                    "https://attack.mitre.org/software/S0368/"
                ]
            },
            "stuxnet": {
                "name": "Stuxnet",
                "type": "Industrial Worm",
                "description": "Sophisticated worm targeting industrial control systems, notably Iran's nuclear facilities.",
                "aliases": [],
                "first_seen": "2010",
                "targets": ["Siemens SCADA systems"],
                "impact": "Damaged uranium enrichment centrifuges",
                "mitre_att&ck": ["T1195", "T0889", "T0846"],
                "references": [
                    "https://www.wired.com/2014/11/countdown-to-zero-day-stuxnet/",
                    "https://en.wikipedia.org/wiki/Stuxnet"
                ]
            },
            "zeus": {
                "name": "Zeus",
                "type": "Banking Trojan",
                "description": "One of the most successful banking trojans, stealing banking credentials via man-in-the-browser attacks.",
                "aliases": ["Zbot"],
                "first_seen": "2007",
                "targets": ["Online banking users"],
                "impact": "Stolen millions from bank accounts worldwide",
                "mitre_att&ck": ["T1056", "T1071", "T1082"],
                "references": [
                    "https://www.fbi.gov/news/stories/zeus-virus-spreads-083110",
                    "https://attack.mitre.org/software/S0268/"
                ]
            },
            "mirai": {
                "name": "Mirai",
                "type": "IoT Botnet",
                "description": "Malware that turns networked devices running Linux into remotely controlled bots for DDoS attacks.",
                "aliases": [],
                "first_seen": "2016",
                "targets": ["IoT devices", "DNS providers"],
                "impact": "Used in massive DDoS attacks including the 2016 Dyn attack",
                "mitre_att&ck": ["T0884", "T0885", "T0886"],
                "references": [
                    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa16-288a",
                    "https://en.wikipedia.org/wiki/Mirai_(malware)"
                ]
            },
            "darkcomet": {
                "name": "DarkComet",
                "type": "RAT",
                "description": "Remote Access Trojan (RAT) used for surveillance and data theft.",
                "aliases": [],
                "first_seen": "2008",
                "targets": ["Windows systems"],
                "impact": "Used in Syrian conflict for surveillance",
                "mitre_att&ck": ["T1219", "T1056", "T1071"],
                "references": [
                    "https://www.malwarebytes.com/blog/news/2012/08/darkcomet-rat-used-by-syrian-government",
                    "https://attack.mitre.org/software/S0129/"
                ]
            },
            "cryptolocker": {
                "name": "CryptoLocker",
                "type": "Ransomware",
                "description": "Early ransomware that encrypted files and demanded Bitcoin payment.",
                "aliases": [],
                "first_seen": "2013-09",
                "targets": ["Windows users"],
                "impact": "Extracted ~$3 million before takedown",
                "mitre_att&ck": ["T1486", "T1140", "T1071"],
                "references": [
                    "https://www.fbi.gov/news/stories/cryptolocker-scourge-recalled-082316",
                    "https://en.wikipedia.org/wiki/CryptoLocker"
                ]
            },
            "solarwinds": {
                "name": "SolarWinds",
                "type": "Supply Chain Attack",
                "description": "Sophisticated supply chain attack compromising SolarWinds Orion software updates.",
                "aliases": ["SUNBURST"],
                "first_seen": "2020",
                "targets": ["Government agencies", "Tech companies"],
                "impact": "Compromised multiple US government agencies",
                "mitre_att&ck": ["T1195", "T1078", "T1133"],
                "references": [
                    "https://www.cisa.gov/solarwinds",
                    "https://attack.mitre.org/software/S0559/"
                ]
            }
        }

    def analyze_threat(self, indicator):
        """Main analysis function with comprehensive error handling"""
        try:
            if not indicator or not isinstance(indicator, str):
                raise ValueError("Invalid indicator format")
            
            analysis = {
                'indicator': indicator,
                'type': self._detect_indicator_type(indicator),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'results': {}
            }
            
            if analysis['type'] == 'ip':
                analysis['results'].update(self._analyze_ip(indicator))
            elif analysis['type'] == 'domain':
                analysis['results'].update(self._analyze_domain(indicator))
            elif analysis['type'] == 'hash':
                analysis['results'].update(self._analyze_hash(indicator))
            elif analysis['type'] == 'malware':
                analysis['results'].update(self._analyze_malware(indicator))
            else:
                analysis['results'].update(self._analyze_keyword(indicator))
                
            return analysis
            
        except Exception as e:
            return {
                'indicator': indicator,
                'error': f"Analysis failed: {str(e)}",
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def _detect_indicator_type(self, indicator):
        """Determine the type of indicator with validation"""
        indicator = indicator.strip()
        
        # IP address pattern (IPv4)
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        # Domain pattern (simplified)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        
        # Hash patterns (MD5, SHA-1, SHA-256)
        hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$'
        }
        
        if re.match(ip_pattern, indicator):
            return 'ip'
        elif re.match(domain_pattern, indicator, re.IGNORECASE):
            return 'domain'
        else:
            for hash_type, pattern in hash_patterns.items():
                if re.match(pattern, indicator, re.IGNORECASE):
                    return 'hash'
            
            if indicator.lower() in self.malware_db:
                return 'malware'
                
            return 'keyword'
    
    def _analyze_ip(self, ip):
        """Analyze an IP address with mock API responses"""
        result = {}
        
        # Mock AbuseIPDB response
        result['abuseipdb'] = {
            'abuse_confidence': 85,
            'country': 'US',
            'isp': 'Example ISP',
            'reports': 42,
            'last_reported': '2023-10-25T14:30:00Z'
        }
        
        # Mock VirusTotal response
        result['virustotal'] = {
            'reputation': -15,
            'detections': {
                'malicious': 5,
                'suspicious': 2,
                'harmless': 42
            },
            'asn': 'AS12345',
            'network': '192.0.2.0/24'
        }
        
        return result
    
    def _analyze_domain(self, domain):
        """Analyze a domain with mock API responses"""
        result = {}
        
        # Mock VirusTotal response
        result['virustotal'] = {
            'categories': ['parking', 'malware'],
            'detections': {
                'malicious': 3,
                'suspicious': 1,
                'harmless': 35
            },
            'registrar': 'Example Registrar Inc.',
            'creation_date': '2010-05-15',
            'last_analysis_date': '2023-10-25'
        }
        
        # Mock OTX response
        result['otx'] = {
            'pulse_count': 8,
            'related_malware': ['Emotet', 'TrickBot'],
            'tags': ['phishing', 'malware']
        }
        
        return result
    
    def _analyze_hash(self, file_hash):
        """Analyze a file hash with mock API responses"""
        result = {}
        
        # Mock VirusTotal response
        result['virustotal'] = {
            'type': 'PE32 executable',
            'detections': {
                'malicious': 45,
                'suspicious': 5,
                'harmless': 2
            },
            'names': ['malware.exe', 'trojan.xyz'],
            'size': '2.5 MB',
            'first_seen': '2023-10-20',
            'signature_info': {
                'signer': 'Unknown',
                'verified': False
            }
        }
        
        return result
    
    def _analyze_malware(self, malware_name):
        """Analyze a malware name with local database and mock API responses"""
        malware_name = malware_name.lower()
        result = {}
        
        if malware_name in self.malware_db:
            result['malware_info'] = self.malware_db[malware_name]
        else:
            result['malware_info'] = {'warning': 'Malware not found in local database'}
        
        # Mock OTX response
        result['otx'] = {
            'pulse_count': 15,
            'related_indicators': {
                'ips': ['1.2.3.4', '5.6.7.8'],
                'domains': ['malicious.com', 'c2.example.com'],
                'hashes': ['a1b2c3...', 'd4e5f6...']
            },
            'recent_activity': {
                'last_30d': 8,
                'last_90d': 22
            }
        }
        
        # Mock VirusTotal response
        result['virustotal'] = {
            'malware_name': malware_name,
            'detections': {
                'last_24h': 42,
                'last_7d': 315,
                'last_30d': 1200
            },
            'behavior': {
                'network_activity': ['C2 communication', 'DNS queries'],
                'file_operations': ['Creates autorun registry keys', 'Drops executable files']
            }
        }
        
        return result
    
    def _analyze_keyword(self, keyword):
        """Analyze a generic keyword"""
        return {
            'warning': 'No specific threat intelligence found',
            'suggestion': 'Try a more specific indicator (IP, domain, hash, or known malware name)',
            'searched_sources': ['VirusTotal', 'OTX', 'AbuseIPDB']
        }

def display_results(analysis):
    """Display analysis results in JSON format"""
    print(json.dumps(analysis, indent=2))

def main():
    """Main interactive function"""
    # Check if input was provided
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "Please provide a threat indicator to analyze",
            "usage": "python threat_intel.py <indicator>",
            "examples": [
                "python threat_intel.py 1.1.1.1",
                "python threat_intel.py wannacry"
            ]
        }, indent=2))
        sys.exit(1)
    
    indicator = ' '.join(sys.argv[1:])
    tool = ThreatIntelligenceTool()
    
    try:
        analysis = tool.analyze_threat(indicator)
        display_results(analysis)
    except Exception as e:
        print(json.dumps({
            "error": f"An error occurred during analysis: {str(e)}",
            "indicator": indicator,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, indent=2))
        sys.exit(1)

if __name__ == "__main__":
    main()