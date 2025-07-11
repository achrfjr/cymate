import dbConnection from "../db/db.js";

const populateDatabase = async () => {
    try {
        console.log("🚀 Starting database population...");
        const db = await dbConnection();

        // Create categories
        console.log("📂 Creating categories...");
        const categories = [
            { name: 'Network', description: 'Tools related to network security and scanning' },
            { name: 'Web', description: 'Tools related to web application security and vulnerabilities' },
            { name: 'Threat Intelligence', description: 'Tools for analyzing and correlating threat data' },
            { name: 'Malware', description: 'Tools related to malware detection and analysis' }
        ];

        for (const category of categories) {
            await db.run(
                "INSERT OR IGNORE INTO Categories (name, description) VALUES (?, ?)",
                [category.name, category.description]
            );
            console.log(`✅ Category '${category.name}' added`);
        }

        // Insert Web Security Tools
        console.log("🌐 Adding Web Security Tools...");
        const webTools = [
            {
                name: 'SSRF Vulnerability Testing',
                description: 'Tool to test for SSRF by sending crafted requests and analyzing responses',
                executionCmd: 'python tools\\ssrf-vulnerability-tool.py',
                path: 'tools\\ssrf-vulnerability-tool.py'
            },
            {
                name: 'Web Config Scanner',
                description: 'Scans for misconfigurations and default credentials in web apps',
                executionCmd: 'python tools\\web-config-scanner.py <url>',
                path: 'tools\\web-config-scanner.py'
            },
            {
                name: 'crypto',
                description: 'Demonstrates insecure hashing and encryption practices (e.g., MD5, hardcoded keys)',
                executionCmd: 'python tools\\crypto-demo.py',
                path: 'tools\\crypto-demo.py'
            },
            {
                name: 'design-checker',
                description: 'Analyzes design documents for insecure patterns like SQL injection, no rate limiting, etc.',
                executionCmd: 'python tools\\design-checker.py',
                path: 'tools\\design-checker.py'
            },
            {
                name: 'vuln',
                description: 'Scans Python requirements.txt for vulnerable packages using OSV API',
                executionCmd: 'python tools\\vuln.py',
                path: 'tools\\vuln.py'
            },
            {
                name: 'Software Integrity',
                description: 'Checks for software integrity issues',
                executionCmd: 'python tools\\software-integrity.py',
                path: 'tools\\software-integrity.py'
            },
            {
                name: 'Logging Failure',
                description: 'Detects logging configuration failures',
                executionCmd: 'python tools\\logging-failure.py',
                path: 'tools\\logging-failure.py'
            },
            {
                name: 'Identification Failure',
                description: 'Identifies authentication and identification failures',
                executionCmd: 'python tools\\identification-failure.py',
                path: 'tools\\identification-failure.py'
            }
        ];

        for (const tool of webTools) {
            await db.run(
                `INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES 
                (?, ?, ?, ?, (SELECT id FROM Categories WHERE name='Web'))`,
                [tool.name, tool.description, tool.executionCmd, tool.path]
            );
            console.log(`✅ Web tool '${tool.name}' added`);
        }

        // Insert Network Security Tools
        console.log("🔗 Adding Network Security Tools...");
        const networkTools = [
            {
                name: 'DNS Hostname Scanning',
                description: 'Tool to analyze DNS records and detect subdomains',
                executionCmd: 'python tools\\dns-hostname-scanning.py',
                path: 'tools\\dns-hostname-scanning.py'
            },
            {
                name: 'Firewall and ACL Testing',
                description: 'Tool to check if a port is blocked by a firewall',
                executionCmd: 'python tools\\firewall-and-acl-testing.py',
                path: 'tools\\firewall-and-acl-testing.py'
            },
            {
                name: 'IP Scanning',
                description: 'Tool to scan an IP range and detect live hosts',
                executionCmd: 'python tools\\ipscanning.py',
                path: 'tools\\ipscanning.py'
            },
            {
                name: 'Port Scanning',
                description: 'Tool to scan ports and detect open services',
                executionCmd: 'python tools\\port-scanning.py',
                path: 'tools\\port-scanning.py'
            },
            {
                name: 'Protocol Analysis',
                description: 'Tool to detect protocols and check for security risks',
                executionCmd: 'python tools\\protocol-ana.py',
                path: 'tools\\protocol-ana.py'
            },
            {
                name: 'Service Detection',
                description: 'Tool to detect running services and their versions',
                executionCmd: 'python tools\\service-detect.py',
                path: 'tools\\service-detect.py'
            },
            {
                name: 'Subnet and VLAN Scanning',
                description: 'Tool to scan subnets and detect improper VLAN configurations',
                executionCmd: 'python tools\\subnet-and-vlan-scanning.py',
                path: 'tools\\subnet-and-vlan-scanning.py'
            },
            {
                name: 'Latency Testing',
                description: 'Tool to measure network latency and packet loss',
                executionCmd: 'python tools\\test-latency.py',
                path: 'tools\\test-latency.py'
            }
        ];

        for (const tool of networkTools) {
            await db.run(
                `INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES 
                (?, ?, ?, ?, (SELECT id FROM Categories WHERE name='Network'))`,
                [tool.name, tool.description, tool.executionCmd, tool.path]
            );
            console.log(`✅ Network tool '${tool.name}' added`);
        }

        // Insert Malware Detection Tools
        console.log("🦠 Adding Malware Detection Tools...");
        const malwareTools = [
            {
                name: 'File Scanner',
                description: 'Scans files for malicious patterns and calculates file hashes',
                executionCmd: 'python tools\\file-scanner.py',
                path: 'tools\\file-scanner.py'
            },
            {
                name: 'URL Scanner',
                description: 'Scans URLs for potentially malicious patterns and suspicious characteristics',
                executionCmd: 'python tools\\url-scanner.py',
                path: 'tools\\url-scanner.py'
            }
        ];

        for (const tool of malwareTools) {
            await db.run(
                `INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES 
                (?, ?, ?, ?, (SELECT id FROM Categories WHERE name='Malware'))`,
                [tool.name, tool.description, tool.executionCmd, tool.path]
            );
            console.log(`✅ Malware tool '${tool.name}' added`);
        }

        // Insert Threat Intelligence Tools
        console.log("🎯 Adding Threat Intelligence Tools...");
        const threatTools = [
            {
                name: 'Threat Intelligence Scanner',
                description: 'Collects and analyzes threat intelligence from various sources',
                executionCmd: 'python tools\\threat.py',
                path: 'tools\\threat.py'
            }
        ];

        for (const tool of threatTools) {
            await db.run(
                `INSERT OR IGNORE INTO SecurityTools (name, description, executionCmd, path, categoryId) VALUES 
                (?, ?, ?, ?, (SELECT id FROM Categories WHERE name='Threat Intelligence'))`,
                [tool.name, tool.description, tool.executionCmd, tool.path]
            );
            console.log(`✅ Threat Intelligence tool '${tool.name}' added`);
        }

        console.log("🎉 Database population completed successfully!");
        console.log("\n📊 Summary:");
        
        // Get counts
        const categoryCount = await db.get("SELECT COUNT(*) as count FROM Categories");
        const toolCount = await db.get("SELECT COUNT(*) as count FROM SecurityTools");
        
        console.log(`- Categories: ${categoryCount.count}`);
        console.log(`- Security Tools: ${toolCount.count}`);
        
        process.exit(0);
    } catch (error) {
        console.error("❌ Error populating database:", error);
        process.exit(1);
    }
};

populateDatabase(); 