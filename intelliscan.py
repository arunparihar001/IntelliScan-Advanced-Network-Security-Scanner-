# IntelliScan: Port Scanner with Threat Intelligence Integration + Web Interface + Report + PDF + Progress Bar

import socket
import requests
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file, Response
import webbrowser
import os
import time
import threading
import subprocess
import re

# === CONFIG ===
ABUSEIPDB_API_KEY =os.getenv("ABUSEIPDB_API_KEY", "")
SCAN_TIMEOUT = 1  # Seconds

# Common ports to scan
COMMON_PORTS = {
    "web": [80, 443, 8080, 8443],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "file": [20, 21, 22, 23],
    "database": [1433, 1434, 3306, 3389, 5432, 6379, 27017],
    "remote": [22, 23, 3389, 5900],
    "gaming": [25565, 27015, 7777],
    "all": [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
}

app = Flask(__name__)

# Global variables
scan_progress = 0
scan_logs = []
scan_results = None

# Create reports directory if it doesn't exist
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

def log_message(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    scan_logs.append(log_entry)
    return log_entry

def run_nmap_scan(target, scan_type="quick"):
    """Run Nmap scan using Docker and return results"""
    try:
        # Different scan types
        nmap_options = {
            "quick": "-F -T4",  # Quick scan of most common ports
            "full": "-p- -T4",  # Full port scan
            "aggressive": "-A -T4",  # Aggressive scan with OS and service detection
            "vuln": "-sV --script vuln"  # Vulnerability scan
        }
        
        # Construct the Docker command
        docker_cmd = f"docker run --rm nmap-scanner {nmap_options.get(scan_type, '-F -T4')} {target}"
        log_message(f"Running Nmap scan: {docker_cmd}")
        
        # Run Nmap through Docker
        result = subprocess.run(docker_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return result.stdout
        else:
            log_message(f"Nmap scan failed: {result.stderr}")
            return None
    except Exception as e:
        log_message(f"Error running Nmap scan: {str(e)}")
        return None

def build_nmap_docker():
    """Build the Nmap Docker image if it doesn't exist"""
    try:
        # Check if image exists
        check_cmd = "docker images -q nmap-scanner"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if not result.stdout.strip():
            log_message("Building Nmap Docker image...")
            build_cmd = "docker build -t nmap-scanner -f Dockerfile ."
            result = subprocess.run(build_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                log_message(f"Error building Docker image: {result.stderr}")
                return False
            log_message("Docker image built successfully")
        return True
    except Exception as e:
        log_message(f"Error checking/building Docker image: {str(e)}")
        return False

def parse_nmap_output(nmap_output):
    """Parse Nmap output into structured data"""
    if not nmap_output:
        return None
        
    ports = []
    services = []
    os_info = None
    
    # Parse port information
    port_pattern = r"(\d+)/tcp\s+(\w+)\s+(.+)"
    for line in nmap_output.split('\n'):
        port_match = re.search(port_pattern, line)
        if port_match:
            port, state, service = port_match.groups()
            ports.append(int(port))
            services.append({
                'port': int(port),
                'state': state,
                'service': service.strip()
            })
            
        # Try to get OS information
        if "OS details:" in line:
            os_info = line.split("OS details:")[1].strip()
            
    return {
        'ports': ports,
        'services': services,
        'os_info': os_info,
        'raw_output': nmap_output
    }

# === Port Scanner ===
def scan_ports(target_ip, port_range):
    global scan_progress, scan_logs
    scan_progress = 0
    scan_logs.clear()
    
    open_ports = []
    
    # Handle different port range formats
    if port_range in COMMON_PORTS:
        ports_to_scan = COMMON_PORTS[port_range]
    elif port_range.startswith("specific:"):
        ports_to_scan = [int(p) for p in port_range.split(":")[1].split(",")]
    else:
        start_port, end_port = map(int, port_range.split("-"))
        ports_to_scan = range(start_port, end_port + 1)
    
    total = len(ports_to_scan)
    
    log_message(f"Starting scan for {target_ip}")
    log_message(f"Scanning {total} ports")
    
    for i, port in enumerate(ports_to_scan):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(SCAN_TIMEOUT)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    log_message(f"Port {port} is open")
        except Exception as e:
            log_message(f"Error scanning port {port}: {str(e)}")
        
        # Update progress
        scan_progress = (i + 1) / total * 100
        time.sleep(0.01)  # Small delay to allow progress updates
    
    log_message(f"Scan completed. Found {len(open_ports)} open ports")
    return open_ports

# === Threat Intelligence API ===
def get_threat_score(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": True
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, params=querystring)
        data = response.json()
        
        # Extract detailed information including reports
        threat_info = {
            'ipAddress': data['data']['ipAddress'],
            'isPublic': data['data']['isPublic'],
            'ipVersion': data['data']['ipVersion'],
            'isWhitelisted': data['data']['isWhitelisted'],
            'abuseConfidenceScore': data['data']['abuseConfidenceScore'],
            'countryCode': data['data']['countryCode'],
            'countryName': data['data']['countryName'],
            'usageType': data['data']['usageType'],
            'isp': data['data']['isp'],
            'domain': data['data']['domain'],
            'hostnames': data['data']['hostnames'],
            'isTor': data['data']['isTor'],
            'totalReports': data['data']['totalReports'],
            'numDistinctUsers': data['data']['numDistinctUsers'],
            'lastReportedAt': data['data']['lastReportedAt'],
            'reports': data['data']['reports']
        }
        return threat_info
    except Exception as e:
        log_message(f"Error fetching threat intelligence: {str(e)}")
        return None

# === Risk Assessment ===
def assess_risk(open_ports, threat_info):
    if not threat_info:
        return "Unknown"
        
    score = len(open_ports) * 10 + threat_info['abuseConfidenceScore']
    if score >= 80:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

# === HTML Report Generator ===
def generate_html_report(target, open_ports, threat_info, risk_level, nmap_results=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_color = {
        'High': '#dc3545',
        'Medium': '#ffc107',
        'Low': '#28a745',
        'Unknown': '#6c757d'
    }.get(risk_level, '#6c757d')
    
    # Format threat information
    threat_details = ""
    if threat_info:
        # Format reports
        reports_html = ""
        if threat_info['reports']:
            reports_html = "<div class='reports-section'>"
            for report in threat_info['reports']:
                reports_html += f"""
                    <div class='report-item'>
                        <p><strong>Reported At:</strong> {report['reportedAt']}</p>
                        <p><strong>Comment:</strong> {report['comment']}</p>
                        <p><strong>Categories:</strong> {', '.join(map(str, report['categories']))}</p>
                        <p><strong>Reporter Country:</strong> {report['reporterCountryName']} ({report['reporterCountryCode']})</p>
                    </div>
                """
            reports_html += "</div>"

        threat_details = f"""
            <div class="info-card">
                <div class="info-label">Threat Intelligence Details</div>
                <div class="info-value">
                    <p><strong>IP Address:</strong> {threat_info['ipAddress']}</p>
                    <p><strong>IP Version:</strong> {threat_info['ipVersion']}</p>
                    <p><strong>Is Public:</strong> {threat_info['isPublic']}</p>
                    <p><strong>Is Whitelisted:</strong> {threat_info['isWhitelisted']}</p>
                    <p><strong>Abuse Confidence Score:</strong> {threat_info['abuseConfidenceScore']}%</p>
                    <p><strong>Country:</strong> {threat_info['countryName']} ({threat_info['countryCode']})</p>
                    <p><strong>Usage Type:</strong> {threat_info['usageType']}</p>
                    <p><strong>ISP:</strong> {threat_info['isp']}</p>
                    <p><strong>Domain:</strong> {threat_info['domain']}</p>
                    <p><strong>Hostnames:</strong> {', '.join(threat_info['hostnames']) if threat_info['hostnames'] else 'None'}</p>
                    <p><strong>Is Tor Exit Node:</strong> {threat_info['isTor']}</p>
                    <p><strong>Total Reports:</strong> {threat_info['totalReports']}</p>
                    <p><strong>Distinct Users:</strong> {threat_info['numDistinctUsers']}</p>
                    <p><strong>Last Reported:</strong> {threat_info['lastReportedAt']}</p>
                </div>
            </div>
            <div class="info-card">
                <div class="info-label">Detailed Reports</div>
                <div class="info-value">
                    {reports_html if reports_html else '<p>No detailed reports available</p>'}
                </div>
            </div>
        """
    
    # Add Nmap results section if available
    nmap_section = ""
    if nmap_results:
        nmap_section = f"""
            <div class="report-section">
                <h2 class="section-title">Nmap Scan Results</h2>
                <div class="info-card">
                    <div class="info-label">Operating System</div>
                    <div class="info-value">{nmap_results['os_info'] if nmap_results['os_info'] else 'Not detected'}</div>
                </div>
                <div class="info-card">
                    <div class="info-label">Detected Services</div>
                    <div class="info-value">
                        <table class="service-table">
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                            </tr>
                            {''.join(f"""
                                <tr>
                                    <td>{service['port']}</td>
                                    <td>{service['state']}</td>
                                    <td>{service['service']}</td>
                                </tr>
                            """ for service in nmap_results['services'])}
                        </table>
                    </div>
                </div>
                <div class="info-card">
                    <div class="info-label">Raw Nmap Output</div>
                    <div class="info-value">
                        <pre class="nmap-output">{nmap_results['raw_output']}</pre>
                    </div>
                </div>
            </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IntelliScan Report - {target}</title>
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --forest-dark: #1B4332;
                --forest-medium: #2D6A4F;
                --forest-light: #40916C;
                --forest-accent: #74C69D;
                --forest-bg: #D8F3DC;
                --forest-text: #081C15;
                --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                --glass-bg: rgba(255, 255, 255, 0.7);
                --glass-border: rgba(255, 255, 255, 0.2);
                --glass-shadow: 0 8px 32px rgba(31, 38, 135, 0.15);
            }}

            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: 'Poppins', sans-serif;
                line-height: 1.6;
                color: var(--forest-text);
                background: linear-gradient(135deg, var(--forest-bg), #ffffff);
                min-height: 100vh;
                position: relative;
                overflow-x: hidden;
            }}

            body::before {{
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    radial-gradient(circle at 0% 0%, rgba(64, 145, 108, 0.15) 0%, transparent 50%),
                    radial-gradient(circle at 100% 0%, rgba(64, 145, 108, 0.15) 0%, transparent 50%),
                    radial-gradient(circle at 100% 100%, rgba(64, 145, 108, 0.15) 0%, transparent 50%),
                    radial-gradient(circle at 0% 100%, rgba(64, 145, 108, 0.15) 0%, transparent 50%);
                pointer-events: none;
                z-index: -1;
            }}

            .report-header {{
                background: linear-gradient(135deg, var(--forest-medium), var(--forest-light));
                color: white;
                padding: 3rem 2rem;
                text-align: center;
                position: relative;
                overflow: hidden;
                margin-bottom: 2rem;
            }}

            .report-header::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url('data:image/svg+xml,<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M0 0h20v20H0z" fill="none"/><path d="M10 0l2 6h6l-5 4 2 6-5-4-5 4 2-6-5-4h6z" fill="%23ffffff" fill-opacity="0.05"/></svg>');
                opacity: 0.1;
            }}

            .report-title {{
                font-size: 2.5rem;
                font-weight: 700;
                margin-bottom: 1rem;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
            }}

            .report-subtitle {{
                font-size: 1.2rem;
                opacity: 0.9;
            }}

            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 2rem;
                width: 100%;
                overflow-x: hidden;
            }}

            .report-section {{
                background: var(--glass-bg);
                backdrop-filter: blur(16px);
                -webkit-backdrop-filter: blur(16px);
                border-radius: 24px;
                padding: 2rem;
                margin-bottom: 2rem;
                box-shadow: var(--glass-shadow);
                border: 1px solid var(--glass-border);
            }}

            .section-title {{
                color: var(--forest-dark);
                font-size: 1.5rem;
                font-weight: 600;
                margin-bottom: 1.5rem;
                display: flex;
                align-items: center;
                gap: 12px;
            }}

            .section-title::before {{
                content: '';
                display: inline-block;
                width: 4px;
                height: 24px;
                background: var(--forest-accent);
                border-radius: 2px;
            }}

            .info-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 1.5rem;
            }}

            .info-card {{
                background: rgba(255, 255, 255, 0.9);
                padding: 1.5rem;
                border-radius: 16px;
                box-shadow: var(--card-shadow);
                border: 1px solid var(--glass-border);
                transition: var(--transition);
                width: 100%;
                overflow: hidden;
            }}

            .info-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 15px 40px rgba(0, 0, 0, 0.15);
            }}

            .info-label {{
                color: var(--forest-medium);
                font-weight: 600;
                font-size: 1.1rem;
                margin-bottom: 1rem;
            }}

            .info-value {{
                color: var(--forest-text);
                word-wrap: break-word;
                overflow-wrap: break-word;
                max-width: 100%;
            }}

            .info-value p {{
                margin: 0.8rem 0;
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
                align-items: flex-start;
            }}

            .info-value strong {{
                color: var(--forest-dark);
                min-width: 150px;
                flex-shrink: 0;
            }}

            .risk-badge {{
                display: inline-block;
                padding: 0.8rem 1.5rem;
                border-radius: 30px;
                color: white;
                font-weight: 600;
                font-size: 1.1rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                background: linear-gradient(135deg, {risk_color}, {risk_color}dd);
                box-shadow: 0 4px 15px {risk_color}40;
            }}

            .port-list {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
                gap: 1rem;
                margin-top: 1rem;
            }}

            .port-item {{
                background: linear-gradient(135deg, var(--forest-accent), var(--forest-light));
                color: white;
                padding: 0.8rem;
                border-radius: 12px;
                text-align: center;
                font-family: monospace;
                font-weight: 500;
                box-shadow: 0 4px 15px rgba(116, 198, 157, 0.2);
                transition: var(--transition);
            }}

            .port-item:hover {{
                transform: scale(1.05) translateY(-2px);
                box-shadow: 0 6px 20px rgba(116, 198, 157, 0.3);
            }}

            .service-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                margin-top: 1rem;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
                table-layout: fixed;
            }}

            .service-table th, .service-table td {{
                padding: 1rem;
                text-align: left;
                border-bottom: 1px solid var(--glass-border);
                word-wrap: break-word;
                overflow-wrap: break-word;
            }}

            .service-table th:nth-child(1),
            .service-table td:nth-child(1) {{
                width: 15%;
            }}

            .service-table th:nth-child(2),
            .service-table td:nth-child(2) {{
                width: 15%;
            }}

            .service-table th:nth-child(3),
            .service-table td:nth-child(3) {{
                width: 70%;
            }}

            .nmap-output {{
                background: rgba(0, 0, 0, 0.8);
                color: var(--forest-accent);
                padding: 1.5rem;
                border-radius: 12px;
                font-family: 'Consolas', monospace;
                white-space: pre-wrap;
                overflow-x: auto;
                font-size: 0.9rem;
                line-height: 1.5;
                max-width: 100%;
                word-wrap: break-word;
            }}

            .reports-section {{
                margin-top: 1.5rem;
            }}

            .report-item {{
                background: rgba(255, 255, 255, 0.9);
                padding: 1.5rem;
                margin-bottom: 1rem;
                border-radius: 12px;
                border: 1px solid var(--glass-border);
                transition: var(--transition);
                width: 100%;
                overflow: hidden;
            }}

            .report-item:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            }}

            .report-item p {{
                margin: 0.8rem 0;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }}

            .footer {{
                text-align: center;
                padding: 2rem;
                color: var(--forest-medium);
                font-size: 0.9rem;
                margin-top: 3rem;
            }}

            @media (max-width: 768px) {{
                .container {{
                    padding: 0 1rem;
                }}

                .report-title {{
                    font-size: 2rem;
                }}

                .info-grid {{
                    grid-template-columns: 1fr;
                }}

                .port-list {{
                    grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
                }}

                .info-value p {{
                    flex-direction: column;
                    gap: 0.2rem;
                }}

                .info-value strong {{
                    min-width: 100%;
                }}

                .service-table {{
                    display: block;
                    overflow-x: auto;
                    white-space: nowrap;
                }}

                .service-table th, .service-table td {{
                    white-space: normal;
                    min-width: 120px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="report-header">
            <h1 class="report-title">IntelliScan Security Report</h1>
            <p class="report-subtitle">Advanced Network Security Analysis</p>
        </div>

        <div class="container">
            <div class="report-section">
                <h2 class="section-title">Target Information</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Target IP Address</div>
                        <div class="info-value">{target}</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Scan Timestamp</div>
                        <div class="info-value">{timestamp}</div>
                    </div>
                </div>
            </div>

            <div class="report-section">
                <h2 class="section-title">Security Assessment</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Risk Level</div>
                        <div class="info-value">
                            <span class="risk-badge">{risk_level}</span>
                        </div>
                    </div>
                    {threat_details}
                </div>
            </div>

            <div class="report-section">
                <h2 class="section-title">Open Ports Analysis</h2>
                <div class="info-card">
                    <div class="info-label">Detected Open Ports</div>
                    <div class="port-list">
                        {''.join(f'<div class="port-item">{port}</div>' for port in open_ports) if open_ports else '<div class="info-value">No open ports detected</div>'}
                    </div>
                </div>
            </div>

            {nmap_section}

            <div class="footer">
                <p>Generated by IntelliScan - Advanced Network Security Tool</p>
                <p>© 2024 All rights reserved</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html

# === Flask Routes ===
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global scan_progress, scan_logs, scan_results
    data = request.get_json()
    target = data.get('ip')
    port_range = data.get('portRange')
    scan_type = data.get('scanType', 'quick')  # Default to quick scan
    
    if not target or not port_range:
        return jsonify({'error': 'Missing IP or port range'}), 400

    # Reset global variables
    scan_progress = 0
    scan_logs.clear()
    scan_results = {'status': 'in_progress'}  # Initialize with status

    # Start scan in a separate thread
    def run_scan():
        global scan_results
        try:
            # Build Docker image if needed
            if not build_nmap_docker():
                raise Exception("Failed to build Nmap Docker image")

            # Perform port scan
            open_ports = scan_ports(target, port_range)
            
            # Run Nmap scan
            nmap_output = run_nmap_scan(target, scan_type)
            nmap_results = parse_nmap_output(nmap_output)
            
            # Get threat intelligence
            threat_info = get_threat_score(target)
            risk_level = assess_risk(open_ports, threat_info)

            # Generate HTML report
            html = generate_html_report(target, open_ports, threat_info, risk_level, nmap_results)
            html_filename = f"scan_report_{target.replace('.', '_')}.html"
            html_path = os.path.join(REPORTS_DIR, html_filename)
            with open(html_path, "w") as f:
                f.write(html)

            # Store results
            scan_results = {
                'status': 'completed',
                'openPorts': open_ports,
                'threatInfo': threat_info,
                'riskLevel': risk_level,
                'nmapResults': nmap_results,
                'htmlReport': html_filename
            }
            log_message("Scan completed successfully")
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            log_message(error_msg)
            scan_results = {
                'status': 'error',
                'error': error_msg
            }

    # Start the scan in a background thread
    thread = threading.Thread(target=run_scan)
    thread.start()

    return jsonify({'message': 'Scan started', 'status': 'in_progress'})

@app.route('/progress')
def get_progress():
    if scan_results is None:
        return jsonify({
            'progress': 0,
            'logs': [],
            'status': 'not_started'
        })
        
    if scan_results.get('status') == 'in_progress':
        return jsonify({
            'progress': scan_progress,
            'logs': scan_logs,
            'status': 'in_progress'
        })
        
    if scan_results.get('status') == 'completed':
        return jsonify({
            'progress': 100,
            'logs': scan_logs,
            'status': 'completed'
        })
        
    if scan_results.get('status') == 'error':
        return jsonify({
            'progress': scan_progress,
            'logs': scan_logs,
            'status': 'error',
            'error': scan_results.get('error')
        })
        
    return jsonify({
        'progress': 0,
        'logs': [],
        'status': 'unknown'
    })

@app.route('/results')
def get_results():
    if scan_results is None:
        return jsonify({'error': 'No scan has been initiated'}), 400
        
    if scan_results.get('status') == 'in_progress':
        return jsonify({
            'status': 'in_progress',
            'message': 'Scan is still in progress'
        }), 202
        
    if scan_results.get('status') == 'error':
        return jsonify({
            'status': 'error',
            'error': scan_results.get('error', 'Unknown error occurred')
        }), 400
        
    if scan_results.get('status') == 'completed':
        return jsonify(scan_results)
        
    return jsonify({'error': 'Invalid scan status'}), 400

@app.route('/reports/<path:filename>')
def download_report(filename):
    try:
        return send_file(os.path.join(REPORTS_DIR, filename))
    except Exception as e:
        return jsonify({'error': f'Report not found: {str(e)}'}), 404

# Add new route to get available scan types
@app.route('/scan-types')
def get_scan_types():
    return jsonify({
        'portRanges': {
            'web': 'Web Services (80, 443, 8080, 8443)',
            'mail': 'Mail Services (25, 110, 143, 465, 587, 993, 995)',
            'file': 'File Transfer (20, 21, 22, 23)',
            'database': 'Database Services (1433, 1434, 3306, 3389, 5432, 6379, 27017)',
            'remote': 'Remote Access (22, 23, 3389, 5900)',
            'gaming': 'Gaming Services (25565, 27015, 7777)',
            'all': 'All Common Ports'
        },
        'nmapScans': {
            'quick': 'Quick Scan (Most Common Ports)',
            'full': 'Full Port Scan',
            'aggressive': 'Aggressive Scan (OS & Service Detection)',
            'vuln': 'Vulnerability Scan'
        }
    })

# === Entry Point ===
if __name__ == "__main__":
    app.run(debug=True, port=5000)
